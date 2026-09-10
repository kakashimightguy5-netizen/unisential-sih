#!/usr/bin/env python3
"""EXP-0020 — refined rate-of-change rule with an in-bounds-predecessor gate.

Direct follow-up to EXP-0019 (recommended in its logs). Measurement only;
`ml/iforest_detector.run_detector` is NOT modified and NOT called. EXP-0017 is
reproduced from its checksummed saved artifact (`exp0017_operational.load_result`)
and asserted element-wise `comb == protocol | pressure | IF` with whole-TEST
confusion (4767, 40, 2166, 2374) before any score is read.

EXP-0019 found `rate_w = |Δp|/Δt` (max step rate into a 5 s window) genuinely
separates the CMRI EXP-0017 misses from Normal (Mann-Whitney p = 2.07e-19, right
direction, 26.65% new recall) but failed the false-positive bar (0.936%), and 35 of
its 45 pure-Normal false positives were a window inheriting a large rate from a pair
stepping DOWN out of a preceding anomalous window.

EXP-0020 adds ONE change: a pair `(i-1, i)` is scored only if `Δt > 0` AND the
EARLIER sample `p_{i-1}` is within the EXP-0016 frozen TRAIN-normal pressure bounds
[0.482759, 38.7471] (from the verified EXP-0017 artifact). The later sample is
deliberately unconstrained. Everything else — feature, TRAIN-normal-percentile
calibration, evaluation cohort, decision rule, identity gates — is identical to
EXP-0019 and reused from its (frozen, unmodified) module.

Bounds/coefficients are empirical TRAIN-normal statistics, not a physical spec
(register map/scale undocumented); one testbed; egress only.
See EXPERIMENT_LOG.md / DECISION_LOG.md (EXP-0020, 2026-09-10).
"""
from __future__ import annotations

import json
import math
import os
import platform
from importlib.metadata import version
from pathlib import Path
from typing import Mapping

import numpy as np
from scipy.stats import mannwhitneyu

from exp0017_operational import load_result
from exp0019_pressure_rate_plausibility import (
    Blocks, EXP0017_TEST_CONFUSION, align_egress_pressure_timeseries, bucket_of,
    classify_verdict, confusion, _cohort_mask, _q,
)

ROOT = Path(__file__).resolve().parent.parent
RESULT_PATH = ROOT / "data" / "experiments" / "exp0020_pressure_rate_gated.json"
EXP0019_RESULT_PATH = ROOT / "data" / "experiments" / "exp0019_pressure_rate_plausibility.json"
CMRI = 2
CUTOFF_PERCENTILE = 99.9         # unchanged from EXP-0019
SIGNAL_ALPHA = 0.01


# --------------------------------------------------------------- gated rate feature

def eligible_pairs(series, bounds):
    """Yield (earlier_bucket, later_bucket, rate) for every pair with Δt > 0 whose
    EARLIER sample pressure is within `bounds` (inclusive)."""
    lo, hi = bounds
    for (t0, p0), (t1, p1) in zip(series, series[1:]):
        dt = t1 - t0
        if dt <= 0 or not (lo <= p0 <= hi):
            continue
        yield bucket_of(t0), bucket_of(t1), abs(p1 - p0) / dt


def window_max_gated_rate(series, bounds):
    """rate_w = max eligible step rate over pairs whose LATER sample is in w.
    Also returns {later_bucket: earlier_bucket that produced the max} for the
    boundary-artifact re-check."""
    by_win: dict[int, float] = {}
    src: dict[int, int] = {}
    for eb, lb, r in eligible_pairs(series, bounds):
        if lb not in by_win or r > by_win[lb]:
            by_win[lb] = float(r)
            src[lb] = eb
    return by_win, src


def train_normal_gated_rates(series, blocks: Blocks, bounds) -> np.ndarray:
    out = [
        r for eb, lb, r in eligible_pairs(series, bounds)
        if blocks.label(eb) == "train_normal" and blocks.label(lb) == "train_normal"
    ]
    return np.asarray(out, dtype=float)


# --------------------------------------------------------------- experiment

def run_experiment() -> dict:
    # ---- reproduce EXP-0017 from its checksummed artifact (identity gate) ----
    R = load_result()
    comb = np.asarray(R.comb_pred, dtype=int)
    prot = np.asarray(R.protocol_pred, dtype=int)
    press = np.asarray(R.pressure_pred, dtype=int)
    ifp = np.asarray(R.if_pred, dtype=int)
    y = np.asarray(R.y_test, dtype=int)
    test_windows = R.test_windows
    gate_elementwise = bool(np.array_equal(comb, prot | press | ifp))
    tn = int(((comb == 0) & (y == 0)).sum())
    fp = int(((comb == 1) & (y == 0)).sum())
    fn = int(((comb == 0) & (y == 1)).sum())
    tp = int(((comb == 1) & (y == 1)).sum())
    gate_confusion = (tn, fp, fn, tp) == EXP0017_TEST_CONFUSION
    if not (gate_elementwise and gate_confusion):
        raise RuntimeError(
            f"EXP-0017 identity gate failed: elementwise={gate_elementwise} "
            f"confusion={(tn, fp, fn, tp)} vs {EXP0017_TEST_CONFUSION}"
        )
    bounds = (float(R.pressure_bounds[0]), float(R.pressure_bounds[1]))
    if bounds != (0.482759, 38.7471):
        raise RuntimeError(f"EXP-0016 pressure bounds changed: {bounds}")

    # ---- gated rate feature, blocks, TRAIN-normal calibration ----
    blocks = Blocks()
    if (blocks.split_id, blocks.split_sha256) != (R.split_id, R.split_sha256):
        raise RuntimeError("manifest identity differs from the EXP-0017 artifact")
    series = align_egress_pressure_timeseries()
    by_win, src = window_max_gated_rate(series, bounds)
    tn_rates = train_normal_gated_rates(series, blocks, bounds)
    if len(tn_rates) < 500:
        raise RuntimeError("too few eligible TRAIN-normal step rates for a percentile bound")

    pct = {
        "p50": float(np.percentile(tn_rates, 50)),
        "p90": float(np.percentile(tn_rates, 90)),
        "p99": float(np.percentile(tn_rates, 99)),
        "p99_9": float(np.percentile(tn_rates, 99.9)),
        "p99_99": float(np.percentile(tn_rates, 99.99)),
        "max": float(np.max(tn_rates)),
    }
    cutoff = float(np.percentile(tn_rates, CUTOFF_PERCENTILE))
    cutoff_max = pct["max"]

    def fired_for(thr: float) -> np.ndarray:
        return np.array(
            [int(by_win.get(int(w.w_index), -1.0) > thr) for w in test_windows],
            dtype=int,
        )

    rate_fired = fired_for(cutoff)
    rate_fired_maxbound = fired_for(cutoff_max)
    rate_defined = np.array([int(w.w_index) in by_win for w in test_windows], dtype=bool)

    comb_by_bucket = {int(w.w_index): int(comb[i]) for i, w in enumerate(test_windows)}
    attack_by_bucket = {int(w.w_index): int(w.is_attack) for w in test_windows}

    # ---- cohort: CMRI TEST windows EXP-0017 misses ----
    normal_mask = _cohort_mask(test_windows, 0, "pure_normal")
    n_neg = int(normal_mask.sum())
    rate_normal_fp = int(rate_fired[normal_mask].sum())
    new_normal_fp_rate = rate_normal_fp / n_neg
    mb_normal_fp = int(rate_fired_maxbound[normal_mask].sum())
    comb_mb = (comb | rate_fired_maxbound).astype(int)
    mb_tp = int(((comb_mb == 1) & (y == 1)).sum())
    mb_fp = int(((comb_mb == 1) & (y == 0)).sum())
    mb_combined_precision = mb_tp / (mb_tp + mb_fp) if (mb_tp + mb_fp) else 0.0

    # boundary-artifact re-check (should now be near 0)
    fp_boundary_artifact = 0
    for w, m, f in zip(test_windows, normal_mask, rate_fired):
        if not (m and f):
            continue
        eb = src.get(int(w.w_index))
        if eb is not None and (comb_by_bucket.get(eb, 0) == 1 or attack_by_bucket.get(eb, 0) == 1):
            fp_boundary_artifact += 1

    cohorts_out = []
    missed_defined = {}
    for mode in ("pure", "dominant", "containing"):
        cmri = _cohort_mask(test_windows, CMRI, mode)
        missed = cmri & (comb == 0)
        missed_def = missed & rate_defined
        for tag, arr in (("p99.9", rate_fired), ("train_normal_max", rate_fired_maxbound)):
            hits = int(arr[missed_def].sum())
            rec = hits / int(missed_def.sum()) if missed_def.sum() else 0.0
            cohorts_out.append({
                "cohort": mode, "cutoff_variant": tag,
                "cmri_windows": int(cmri.sum()),
                "exp0017_missed": int(missed.sum()),
                "missed_with_defined_rate": int(missed_def.sum()),
                "missed_rate_undefined_under_gate": int((missed & ~rate_defined).sum()),
                "new_detections": hits,
                "new_recall": rec, "new_recall_pct": round(100 * rec, 3),
            })
        missed_defined[mode] = missed_def

    pure_missed = missed_defined["pure"]
    new_recall = (
        int(rate_fired[pure_missed].sum()) / int(pure_missed.sum())
        if pure_missed.sum() else 0.0
    )
    new_recall_maxbound = (
        int(rate_fired_maxbound[pure_missed].sum()) / int(pure_missed.sum())
        if pure_missed.sum() else 0.0
    )

    # ---- threshold-independent signal test ----
    e_missed = np.array(
        [by_win[int(w.w_index)] for w, m in zip(test_windows, pure_missed) if m],
        dtype=float,
    )
    e_normal = np.array(
        [by_win[int(w.w_index)] for w, m in zip(test_windows, normal_mask)
         if m and int(w.w_index) in by_win],
        dtype=float,
    )
    u_stat, p_two = mannwhitneyu(e_missed, e_normal, alternative="two-sided")
    missed_higher = bool(np.median(e_missed) > np.median(e_normal))
    signal_present = bool(p_two < SIGNAL_ALPHA and missed_higher)

    # ---- whole TEST block ----
    comb2 = (comb | rate_fired).astype(int)
    w_tn = int(((comb2 == 0) & (y == 0)).sum())
    w_fp = int(((comb2 == 1) & (y == 0)).sum())
    w_fn = int(((comb2 == 0) & (y == 1)).sum())
    w_tp = int(((comb2 == 1) & (y == 1)).sum())
    combined_precision = w_tp / (w_tp + w_fp) if (w_tp + w_fp) else 0.0

    standalone = {
        "whole_attack_class": confusion(
            int(rate_fired[y == 1].sum()), int((y == 1).sum()), rate_normal_fp, n_neg,
        ),
    }
    noregress = {}
    for name, c in (("NMRI", 1), ("MFCI", 5), ("Recon", 7)):
        m = _cohort_mask(test_windows, c, "pure")
        standalone[name + "_pure"] = confusion(
            int(rate_fired[m].sum()), int(m.sum()), rate_normal_fp, n_neg,
        )
        noregress[name + "_pure"] = {
            "n": int(m.sum()), "exp0017_combined_flagged": int(comb[m].sum()),
            "combined_or_rate_flagged": int(comb2[m].sum()),
            "delta": int(comb2[m].sum()) - int(comb[m].sum()),
        }

    verdict = classify_verdict(new_recall, new_normal_fp_rate, combined_precision)

    # ---- EXP-0019 comparison ----
    e19 = json.loads(EXP0019_RESULT_PATH.read_text(encoding="utf-8"))
    e19_pure = next(c for c in e19["per_cohort_new_detection"]
                    if c["cohort"] == "pure" and c["cutoff_variant"] == "p99.9")
    e19_cmp = {
        "exp0019_new_detections_pure_p99_9": e19_pure["new_detections"],
        "exp0020_new_detections_pure_p99_9": int(rate_fired[pure_missed].sum()),
        "exp0019_pure_normal_fp": e19["decision_rule"]["new_pure_normal_fp"],
        "exp0020_pure_normal_fp": rate_normal_fp,
        "exp0019_boundary_artifact_fp": e19["pure_normal_test_false_positives"][
            "boundary_artifact_diagnostic"][
            "fp_where_max_rate_pair_steps_from_flagged_or_attack_predecessor"],
        "exp0020_boundary_artifact_fp": fp_boundary_artifact,
        "exp0019_verdict": e19["decision_rule"]["verdict"],
    }

    return {
        "status": "VALIDATED — GATED RATE RULE BUILT AND SCORED; run_detector NOT modified",
        "experiment": "EXP-0020",
        "hypothesis": (
            "The EXP-0019 rate rule failed the FP bar mainly because it scored jumps "
            "OUT of anomalous predecessors. Gating on an in-EXP-0016-bounds earlier "
            "sample should keep the CMRI recall while removing those false positives."
        ),
        "predecessor_eligibility_rule": (
            "pair (i-1,i) scored iff Δt>0 AND BOUND_LOW <= p_{i-1} <= BOUND_HIGH, "
            f"BOUND_LOW/HIGH = {bounds} (EXP-0016 frozen bounds from the EXP-0017 "
            "artifact); the later sample p_i is NOT constrained"
        ),
        "identity_gates": {
            "exp0017_artifact_loaded_and_verified": True,
            "comb_equals_protocol_or_pressure_or_if": gate_elementwise,
            "whole_test_confusion_matches_exp0017": bool(gate_confusion),
            "exp0017_confusion": list(EXP0017_TEST_CONFUSION),
            "exp0016_bounds": list(bounds),
            "run_detector_modified": False,
        },
        "manifest": {"split_id": blocks.split_id, "membership_sha256": blocks.split_sha256},
        "method": {
            "feature": "rate_i = |p_i - p_{i-1}| / (t_i - t_{i-1}) over ELIGIBLE pairs",
            "per_window": "rate_w = max eligible step rate over pairs whose later "
                          "sample is in w; undefined if no eligible pair",
            "cutoff_reasoning": "TRAIN-normal 99.9th percentile of the gated rate "
                                "(same approach as EXP-0019, re-fit on the gated feature)",
            "train_normal_gated_rate_percentiles": pct,
            "train_normal_eligible_pairs": int(len(tn_rates)),
            "cutoff_primary_p99_9": cutoff,
            "cutoff_strict_train_normal_max": cutoff_max,
        },
        "evaluation_cohort": (
            "CMRI-labelled TEST windows with EXP-0017 comb_pred == 0 and a defined "
            "gated rate_w; 'new detection' = gated rate rule fires AND comb_pred == 0"
        ),
        "decision_rule": {
            "strong": "new pure-CMRI recall >= 25% AND new pure-Normal FP <= 0.30% "
                      "AND combined precision >= 97.0% (unchanged from EXP-0019)",
            "new_pure_cmri_recall": new_recall,
            "new_pure_normal_fp": rate_normal_fp,
            "new_pure_normal_fp_rate": new_normal_fp_rate,
            "combined_precision": combined_precision,
            "verdict": verdict,
            "train_normal_max_bound_variant": {
                "new_pure_cmri_recall": new_recall_maxbound,
                "new_pure_normal_fp": mb_normal_fp,
                "new_pure_normal_fp_rate": mb_normal_fp / n_neg,
                "combined_precision": mb_combined_precision,
                "verdict": classify_verdict(
                    new_recall_maxbound, mb_normal_fp / n_neg, mb_combined_precision,
                ),
            },
        },
        "signal_test": {
            "test": "Mann-Whitney U, two-sided; missed pure-CMRI vs pure-Normal gated rate_w",
            "u_statistic": float(u_stat), "p_value": float(p_two), "alpha": SIGNAL_ALPHA,
            "missed_cmri_rate_higher_than_normal": missed_higher,
            "signal_present_in_hypothesised_direction": signal_present,
            "rate_distribution": {
                "missed_pure_cmri": _q(e_missed),
                "pure_normal_test": _q(e_normal),
                "train_normal_gated_step_rates": _q(tn_rates),
            },
        },
        "per_cohort_new_detection": cohorts_out,
        "pure_normal_test_false_positives": {
            "n_windows": n_neg,
            "gated_rate_rule_fp": rate_normal_fp,
            "gated_rate_rule_fpr_pct": round(100 * new_normal_fp_rate, 4),
            "exp0017_combined_fp": int(comb[normal_mask].sum()),
            "combined_or_rate_fp": int(comb2[normal_mask].sum()),
            "boundary_artifact_fp_recheck": fp_boundary_artifact,
        },
        "exp0019_comparison": e19_cmp,
        "gated_rate_rule_standalone": standalone,
        "no_regression": noregress,
        "whole_test_block_binary_confusion": {
            "cohort": "all 9,347 TEST windows; positive = is_attack",
            "exp0017_comb": dict(zip(("tn", "fp", "fn", "tp"), EXP0017_TEST_CONFUSION)),
            "combined_or_rate": {"tn": w_tn, "fp": w_fp, "fn": w_fn, "tp": w_tp},
            "delta_tn_fp_fn_tp": [
                w_tn - EXP0017_TEST_CONFUSION[0], w_fp - EXP0017_TEST_CONFUSION[1],
                w_fn - EXP0017_TEST_CONFUSION[2], w_tp - EXP0017_TEST_CONFUSION[3],
            ],
            "combined_or_rate_precision": combined_precision,
            "note": "run_detector() NOT modified. Wiring this rule in would change "
                    "EXP-0017's frozen TEST confusion by this delta — a separate decision.",
        },
        "software": {
            "python": platform.python_version(), "numpy": version("numpy"),
            "scipy": version("scipy"), "scikit_learn": version("scikit-learn"),
        },
        "limitations": [
            "Pressure is the ARFF-aligned value, not a live 0x03 byte decode; register "
            "map/scale undocumented.",
            "The cutoff is an empirical TRAIN-normal percentile, not a physical dP/dt "
            "limit; the in-bounds gate uses the empirical EXP-0016 TRAIN-normal range.",
            "1-2 pressure samples per 5 s window; rate_w is one step rate.",
            "EXP-0018/0019/0020 have each scored the frozen TEST set once against a "
            "pressure hypothesis about the missed CMRI — iterative refinement across "
            "experiments is a garden-of-forking-paths risk; a truly held-out "
            "confirmation of any positive result needs data not used here.",
            "Judged only on CMRI windows EXP-0017 already misses; one testbed; egress only.",
        ],
    }


def _json_ready(value):
    if isinstance(value, Mapping):
        return {k: _json_ready(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
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
    dr = r["decision_rule"]
    st = r["signal_test"]
    wt = r["whole_test_block_binary_confusion"]
    fp = r["pure_normal_test_false_positives"]
    m = r["method"]
    rd = st["rate_distribution"]
    cmp = r["exp0019_comparison"]
    mb = dr["train_normal_max_bound_variant"]
    lines = [
        "# EXP-0020 — gated rate-of-change rule (in-bounds predecessor)",
        "",
        f"Predecessor gate: {r['predecessor_eligibility_rule']}",
        f"TRAIN-normal gated |dp|/dt percentiles: p50={m['train_normal_gated_rate_percentiles']['p50']:.4f}  "
        f"p99={m['train_normal_gated_rate_percentiles']['p99']:.4f}  "
        f"p99.9={m['train_normal_gated_rate_percentiles']['p99_9']:.4f}  "
        f"max={m['train_normal_gated_rate_percentiles']['max']:.4f}",
        f"Primary cutoff (p99.9): rate_w > {m['cutoff_primary_p99_9']:.4f}",
        f"run_detector() modified: {r['identity_gates']['run_detector_modified']}",
        "",
        f"## DECISION-RULE VERDICT: {dr['verdict']}",
        f"- new pure-CMRI recall (windows EXP-0017 misses): "
        f"{100 * dr['new_pure_cmri_recall']:.2f}%  (strong >=25%, acceptable >=10%)",
        f"- new pure-Normal FP: {dr['new_pure_normal_fp']}/{fp['n_windows']} = "
        f"{100 * dr['new_pure_normal_fp_rate']:.4f}%  (bar <=0.30%)",
        f"- combined precision (comb OR rate): {100 * dr['combined_precision']:.3f}%  (bar >=97.0%)",
        f"- strict (TRAIN-normal max) cutoff: recall {100 * mb['new_pure_cmri_recall']:.2f}%  "
        f"FP {100 * mb['new_pure_normal_fp_rate']:.4f}%  prec {100 * mb['combined_precision']:.3f}%  "
        f"-> {mb['verdict']}",
        "",
        f"## SIGNAL TEST: {'PRESENT' if st['signal_present_in_hypothesised_direction'] else 'NOT SUPPORTED'}",
        f"- Mann-Whitney U={st['u_statistic']:.0f}  p={st['p_value']:.3g}  (alpha {st['alpha']})",
        f"- median rate_w  missed-CMRI {rd['missed_pure_cmri']['median']:.4f}"
        f"  | Normal {rd['pure_normal_test']['median']:.4f}"
        f"  | TRAIN-normal {rd['train_normal_gated_step_rates']['median']:.4f}",
        "",
        "## EXP-0019 -> EXP-0020 (in-bounds-predecessor gate)",
        f"- new detections (pure, p99.9): {cmp['exp0019_new_detections_pure_p99_9']} "
        f"-> {cmp['exp0020_new_detections_pure_p99_9']}",
        f"- pure-Normal FP: {cmp['exp0019_pure_normal_fp']} -> {cmp['exp0020_pure_normal_fp']}",
        f"- boundary-artifact FP: {cmp['exp0019_boundary_artifact_fp']} -> "
        f"{cmp['exp0020_boundary_artifact_fp']}",
        f"- EXP-0019 verdict: {cmp['exp0019_verdict']}",
        "",
        "## New detections on CMRI windows EXP-0017 misses",
        "| cohort | cutoff | missed (defined rate) | new detections | new recall% |",
        "|---|---|---:|---:|---:|",
    ]
    for c in r["per_cohort_new_detection"]:
        lines.append(
            f"| {c['cohort']} | {c['cutoff_variant']} | {c['missed_with_defined_rate']} "
            f"| {c['new_detections']} | {c['new_recall_pct']:.2f} |"
        )
    lines += [
        "",
        "## Whole 9,347-window TEST block (binary attack/Normal)",
        f"- EXP-0017 comb : TN/FP/FN/TP = "
        f"{wt['exp0017_comb']['tn']}/{wt['exp0017_comb']['fp']}/"
        f"{wt['exp0017_comb']['fn']}/{wt['exp0017_comb']['tp']}",
        f"- comb OR rate  : TN/FP/FN/TP = "
        f"{wt['combined_or_rate']['tn']}/{wt['combined_or_rate']['fp']}/"
        f"{wt['combined_or_rate']['fn']}/{wt['combined_or_rate']['tp']}",
        f"- delta (TN,FP,FN,TP): {wt['delta_tn_fp_fn_tp']}",
        f"- {wt['note']}",
        "",
        "_run_detector NOT modified; wiring this rule in is a separate decision._",
    ]
    return "\n".join(lines)


def main() -> None:
    result = run_experiment()
    write_result_atomic(result)
    print(_format_report(result))
    print(f"\n[result -> {RESULT_PATH}]")


if __name__ == "__main__":
    main()
