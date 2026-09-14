#!/usr/bin/env python3
"""EXP-0030 — IEEE-754 float/representation-provenance detector for the
residual NMRI/CMRI false negatives left by the CURRENTLY WIRED combined
detector (protocol OR pressure-bounds OR rate OR Isolation Forest —
`data/experiments/exp0025_detector.json`).

Framing (repeated everywhere this rule is described, per pre-registration):
this is **float/representation-provenance detection**, NOT physical-anomaly
detection. `ulp_distance_to_train_normal` and the other IEEE-754
bit-structure features most likely reflect that a forged pressure value was
produced by a DIFFERENT quantization/generation pipeline than the real
sensor (e.g. a different float-formatting or rounding path used by the
attack-injection tool), not a property of the physical process the sensor
measures. EXP-0032/EXP-0032b confirmed this signal is real and
run-independent (leave-one-attack-run-out recall never below 50%, mean
~94-95%, across 66 NMRI / 107 CMRI held-out episodes) but built no detector
— this module builds and (conditionally) wires one.

Method, reusing EXP-0032/EXP-0032b building blocks DIRECTLY (not
re-approximated), per pre-registration:
  - `FrozenCombinedWithRateDetector` (below) extends EXP-0032b's
    `FrozenExp0017Detector` with EXP-0025's `RateFloodRule` term, reproducing
    the TRUE currently-wired combined detector (protocol OR pressure-bounds
    OR rate OR Isolation Forest) for TRAIN, VALIDATION, and TEST, verified
    element-wise against the frozen EXP-0025 result before anything is
    trusted (identity gate).
  - Residual cohort ("missed by the current wired rule") = `comb_pred == 0`
    under that TRUE combined rule, for every split (no proxy).
  - Feature set: F2 (IEEE-754 float-representation features) ONLY, per
    pre-registration — F1/F3 excluded (F3 was ruled out in EXP-0032b as
    run-dependent; F1 is the plain numeric baseline, not this experiment's
    subject). `F2_NAMES`, `window_row`, `SeriesIndex`, `build_cohort_frame`
    are imported UNCHANGED from `exp0032_admissible_ceiling_audit`.
  - `_dataset_for`, `_run_family`, `leave_one_run_out` are imported UNCHANGED
    from `exp0032b_ceiling_audit_corrected` — the exact VAL-bootstrap /
    permutation-null / leave-one-attack-run-out machinery EXP-0032b used to
    confirm the raw feature, now applied to the FINAL FITTED model (an
    XGBClassifier over the 7 F2 features, one per attack type: NMRI, CMRI).

ULP-distance metric definition (spelled out precisely, per pre-registration
— new to this line of work): `ulp_distance_to_train_normal(v)` is, despite
its inherited name, the plain absolute value distance `min(|v - r| for r in
R)` to the nearest element of `R`, the SORTED, DEDUPLICATED array of every
raw float64 pressure value observed on TRAIN-normal egress `0x03` response
frames. It is NOT a ULP-count (units-in-the-last-place ordinal) metric —
that naming is inherited unchanged from `exp0032_admissible_ceiling_audit`
and is disclosed here explicitly so it is not misread as an ULP-count.
Nearest-neighbour lookup uses `np.searchsorted` on `R`, comparing the
predecessor and successor candidates and taking the smaller absolute
distance (`nearest_reference_distance`, imported unchanged). Ties (equal
distance to both neighbours) are irrelevant because only the minimum
distance is returned, never an index. Values outside `R`'s observed range
(unseen-exponent range) are NOT extrapolated: `searchsorted` clips to index
0 or `len(R)-1`, so such a value's distance is simply computed against
`R`'s minimum or maximum element — i.e., an out-of-range candidate is
scored purely by its distance to the nearest EDGE of the observed TRAIN-
normal population, which is disclosed as the intended, simplest possible
behaviour (an attacker producing exponent ranges TRAIN never observed does
not get an artificially small "in-range" distance).

Hard constraints (unchanged from the whole missed-NMRI/CMRI line): no
`source` field, no `crc_rate`, no filename/collection/run-ID metadata, no
other testbed artifact. Only features causally available from the egress
`0x03` response frame's decoded pressure value (raw float64 and its
IEEE-754 bit structure) and a TRAIN-normal reference built once from
TRAIN-normal data only. TRAIN/VAL/TEST membership from the frozen
checksummed manifest, never rederived. Feature/hyperparameter/threshold
selection on TRAIN/VAL only; TEST is scored exactly once, at the end.

Pressure is the ARFF-aligned "pressure measurement" value — egress traffic
extracted from Mississippi State ICS testbed dataset, used as a simulated
diode-observer view — never real diode capture data.
See EXPERIMENT_LOG.md / DECISION_LOG.md (EXP-0030).
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
from xgboost import XGBClassifier

from exp0019_pressure_rate_plausibility import Blocks, align_egress_pressure_timeseries
from exp0017_operational import load_result as load_exp0017_result
from exp0025_dos_rate_rule import load_detector_result as load_exp0025_result
from rules import RateFloodRule

from exp0032_admissible_ceiling_audit import (
    F2_NAMES, NMRI, CMRI, WASSERSTEIN_REF_MAX_SIZE, WASSERSTEIN_REF_SEED,
    XGB_PARAMS, MAX_NORMAL_FPR, SeriesIndex, build_cohort_frame, rows_to_matrix,
    fit_threshold, recall_at_threshold,
)
from exp0032b_ceiling_audit_corrected import (
    FrozenExp0017Detector, _dataset_for, _run_family, leave_one_run_out,
    N_BOOTSTRAP_REDUCED, N_PERMUTATIONS_REDUCED, BOOTSTRAP_SEED, PERMUTATION_SEED,
)

ROOT = Path(__file__).resolve().parent.parent
RESULT_PATH = ROOT / "data" / "experiments" / "exp0030_float_provenance_detector.json"

FAMILY = "F2"
# Reduced bootstrap/permutation counts, same disclosed convention as EXP-0032
# (60/20 rather than the spec's illustrative 200/50): every permutation draw
# refits an XGBoost model; kept for session compute-time tractability.
N_BOOTSTRAP, N_PERMUTATIONS = N_BOOTSTRAP_REDUCED, N_PERMUTATIONS_REDUCED

FPR_BAR = 0.0030  # decision rule: combined-detector Normal FPR must stay <= 0.30%
HISTORICAL_PRESSURE_ONLY_CEILING = {"NMRI": 0.7902, "CMRI": 0.5459}  # legibility anchor only


# --------------------------------------------------------------- Fix 1-style: true wired-combined cohort

class FrozenCombinedWithRateDetector(FrozenExp0017Detector):
    """Extends EXP-0032b's `FrozenExp0017Detector` with EXP-0025's
    `RateFloodRule` term, reproducing the CURRENTLY WIRED combined detector
    (protocol OR pressure-bounds OR rate OR Isolation Forest) for TRAIN,
    VALIDATION, and TEST. Verified element-wise against the frozen EXP-0025
    result (`data/experiments/exp0025_detector.json`) before anything else
    is trusted — this is "the current combined production rule", reproduced
    read-only. `iforest_detector.run_detector` itself is never called."""

    def __init__(self, R, exp0025_result):
        super().__init__(R)  # builds self.train/self.val/self.test with protocol/pressure/if_pred

        def train_normal_pps():
            out = []
            for w in self.train["windows"]:
                if w.is_attack == 0:
                    out.append(w.features["packets_per_sec"])
            return out

        rate = RateFloodRule().fit(train_normal_pps())
        self.rate = rate

        def add_rate(block: dict) -> dict:
            pps = [w.features["packets_per_sec"] for w in block["windows"]]
            rate_pred = np.array([rate.evaluate(v).fired for v in pps], dtype=int)
            comb_pred = (block["protocol_pred"] | block["pressure_pred"]
                         | rate_pred | block["if_pred"]).astype(int)
            block = dict(block)
            block["rate_pred"] = rate_pred
            block["comb_pred"] = comb_pred
            return block

        self.train = add_rate(self.train)
        self.val = add_rate(self.val)
        self.test = add_rate(self.test)

        gate = {
            "protocol_pred_matches": bool(np.array_equal(
                self.test["protocol_pred"], np.asarray(exp0025_result.protocol_pred, dtype=int))),
            "pressure_pred_matches": bool(np.array_equal(
                self.test["pressure_pred"], np.asarray(exp0025_result.pressure_pred, dtype=int))),
            "rate_pred_matches": bool(np.array_equal(
                self.test["rate_pred"], np.asarray(exp0025_result.rate_pred, dtype=int))),
            "if_pred_matches": bool(np.array_equal(
                self.test["if_pred"], np.asarray(exp0025_result.if_pred, dtype=int))),
            "comb_pred_matches": bool(np.array_equal(
                self.test["comb_pred"], np.asarray(exp0025_result.comb_pred, dtype=int))),
        }
        self.gate_vs_exp0025 = gate
        if not all(gate.values()):
            raise RuntimeError(
                f"EXP-0030 reproduction of the currently-wired combined detector "
                f"(EXP-0025) failed on TEST: {gate}"
            )


# --------------------------------------------------------------- experiment

def run_experiment() -> dict:
    R = load_exp0017_result()
    exp0025_result = load_exp0025_result()  # the CURRENT wired baseline (protocol|pressure|rate|IF)

    detector = FrozenCombinedWithRateDetector(R, exp0025_result)

    blocks = Blocks()
    series = align_egress_pressure_timeseries()
    si = SeriesIndex(series)
    is_train_normal = np.array(
        [blocks.label(int(b)) == "train_normal" for b in si.bucket_by_pos], dtype=bool,
    )
    train_normal_values = si.values[is_train_normal]
    if len(train_normal_values) < 500:
        raise RuntimeError("too few TRAIN-normal samples for a reference distribution")
    train_normal_sorted = np.sort(np.unique(train_normal_values))
    if len(train_normal_values) > WASSERSTEIN_REF_MAX_SIZE:
        rng0 = np.random.default_rng(WASSERSTEIN_REF_SEED)
        keep = rng0.choice(len(train_normal_values), size=WASSERSTEIN_REF_MAX_SIZE, replace=False)
        train_normal_ref_sample = train_normal_values[np.sort(keep)]
    else:
        train_normal_ref_sample = train_normal_values
    hist_range = (float(train_normal_values.min()), float(train_normal_values.max()))
    bounds = (float(R.pressure_bounds[0]), float(R.pressure_bounds[1]))

    def cohort_frame_for(block_key: str):
        block = getattr(detector, block_key)
        frame = build_cohort_frame(
            block["windows"], si, bounds, train_normal_sorted, train_normal_ref_sample, hist_range,
        )
        frame["missed_by_rule"] = (block["comb_pred"] == 0)
        return frame

    train_frame = cohort_frame_for("train")
    val_frame = cohort_frame_for("val")
    test_frame = cohort_frame_for("test")

    per_attack: dict[str, dict] = {}
    fitted_models: dict[str, dict] = {}

    for attack_name, cohort_key in (("NMRI", "nmri_pure"), ("CMRI", "cmri_pure")):
        family_result = _run_family(
            train_frame, val_frame, test_frame, cohort_key, FAMILY,
            N_BOOTSTRAP, N_PERMUTATIONS, BOOTSTRAP_SEED, PERMUTATION_SEED,
        )

        # Refit the FINAL model deterministically (same XGB_PARAMS/seed/data
        # ordering as _run_family, therefore bit-identical) to obtain the
        # actual classifier + threshold object needed to SCORE TEST windows
        # for wiring, not just to report VAL/TEST summary statistics.
        ds = _dataset_for(train_frame, val_frame, test_frame, cohort_key, FAMILY)
        X_tr, y_tr, _ = ds["train"]
        X_val, y_val, _ = ds["val"]
        clf = None
        threshold = None
        if not family_result.get("insufficient_data") and len(np.unique(y_tr)) >= 2 and len(X_tr) >= 10:
            clf = XGBClassifier(**XGB_PARAMS)
            clf.fit(X_tr, y_tr)
            val_scores = clf.predict_proba(X_val)[:, 1]
            threshold, achieved_fpr = fit_threshold(val_scores[y_val == 0], MAX_NORMAL_FPR)
            reproduced_val_recall = recall_at_threshold(val_scores, y_val, threshold)
            refit_matches_report = math.isclose(
                reproduced_val_recall, family_result["val_recall_point_estimate"], rel_tol=1e-9, abs_tol=1e-9,
            )
        else:
            refit_matches_report = None

        loro = leave_one_run_out(train_frame, val_frame, cohort_key, FAMILY)

        fitted_models[attack_name] = {"clf": clf, "threshold": threshold}
        per_attack[attack_name] = {
            "family_result": family_result,
            "refit_reproduces_reported_val_recall": refit_matches_report,
            "leave_one_run_out_fitted_model": loro,
        }

    # ---- score TEST once: additional OR-condition on the CURRENT wired combined detector ----
    def f2_matrix(frame):
        return rows_to_matrix(frame["rows"], F2_NAMES)

    X_test_f2 = f2_matrix(test_frame)
    float_fires_by_attack = {}
    for attack_name, m in fitted_models.items():
        if m["clf"] is None:
            float_fires_by_attack[attack_name] = np.zeros(len(X_test_f2), dtype=bool)
            continue
        scores = m["clf"].predict_proba(X_test_f2)[:, 1]
        float_fires_by_attack[attack_name] = scores > m["threshold"]

    float_pred = np.zeros(len(X_test_f2), dtype=int)
    for fires in float_fires_by_attack.values():
        float_pred |= fires.astype(int)
    float_pred = float_pred & test_frame["defined"].astype(int)  # undefined rows never fire

    baseline_pred = np.asarray(exp0025_result.comb_pred, dtype=int)
    y_test = np.asarray(exp0025_result.y_test, dtype=int)
    new_pred = (baseline_pred | float_pred).astype(int)

    def confusion(pred):
        tn = int(((pred == 0) & (y_test == 0)).sum())
        fp = int(((pred == 1) & (y_test == 0)).sum())
        fn = int(((pred == 0) & (y_test == 1)).sum())
        tp = int(((pred == 1) & (y_test == 1)).sum())
        return {"tn": tn, "fp": fp, "fn": fn, "tp": tp,
                "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
                "recall": tp / (tp + fn) if (tp + fn) else 0.0}

    baseline_confusion = confusion(baseline_pred)
    new_confusion = confusion(new_pred)

    marginal = {
        "tp_gain": new_confusion["tp"] - baseline_confusion["tp"],
        "fp_gain": new_confusion["fp"] - baseline_confusion["fp"],
        "baseline_fpr": baseline_confusion["fpr"],
        "new_fpr": new_confusion["fpr"],
        "fpr_bar": FPR_BAR,
        "fpr_bar_holds": new_confusion["fpr"] <= FPR_BAR,
    }

    pure_cohort = {}
    for attack_name in ("NMRI", "CMRI"):
        mask = test_frame[f"{attack_name.lower()}_pure"]
        n_pos = int((mask & (y_test == 1)).sum())
        baseline_tp = int((mask & (baseline_pred == 1) & (y_test == 1)).sum())
        new_tp = int((mask & (new_pred == 1) & (y_test == 1)).sum())
        pure_cohort[attack_name] = {
            "n": n_pos,
            "baseline_recall": baseline_tp / n_pos if n_pos else None,
            "new_recall": new_tp / n_pos if n_pos else None,
            "recall_gain": (new_tp - baseline_tp) / n_pos if n_pos else None,
            "historical_pressure_only_ceiling_pct_legibility_anchor":
                100 * HISTORICAL_PRESSURE_ONLY_CEILING[attack_name],
        }

    # ---- decision rule (fixed before running; not amended after seeing results) ----
    def generalizes(attack_name: str) -> bool:
        loro = per_attack[attack_name]["leave_one_run_out_fitted_model"]
        return bool(loro["n_runs_evaluated"] >= 2 and loro["run_dependent"] is False)

    def clears_val_bar(attack_name: str) -> bool:
        fr = per_attack[attack_name]["family_result"]
        if fr.get("insufficient_data"):
            return False
        return bool(fr["clears_permutation_null"])

    verdicts = {}
    for attack_name in ("NMRI", "CMRI"):
        recall_gain = pure_cohort[attack_name]["recall_gain"]
        improves = bool(recall_gain is not None and recall_gain > 0.0)
        qualifies = bool(
            improves and marginal["fpr_bar_holds"] and clears_val_bar(attack_name) and generalizes(attack_name)
        )
        verdicts[attack_name] = {
            "recall_improves_on_test": improves,
            "clears_val_permutation_null_bar": clears_val_bar(attack_name),
            "loro_generalizes_on_fitted_model": generalizes(attack_name),
            "fpr_bar_holds_system_wide": marginal["fpr_bar_holds"],
            "qualifies_for_wiring": qualifies,
        }

    any_qualify = any(v["qualifies_for_wiring"] for v in verdicts.values())
    all_qualify = all(v["qualifies_for_wiring"] for v in verdicts.values())
    if not marginal["fpr_bar_holds"]:
        overall_verdict = "NO-GO (system-wide FPR bar exceeded)"
    elif all_qualify:
        overall_verdict = "GO (both NMRI and CMRI qualify)"
    elif any_qualify:
        qualifying = [k for k, v in verdicts.items() if v["qualifies_for_wiring"]]
        overall_verdict = f"PARTIAL-GO ({', '.join(qualifying)} only)"
    else:
        overall_verdict = "NO-GO (neither category qualifies)"

    return {
        "status": "TESTED — detector build, TEST scored once",
        "experiment": "EXP-0030",
        "framing": (
            "float/representation-provenance detection, NOT physical-anomaly detection: "
            "this rule most likely reflects that forged pressure values were produced by "
            "a different quantization/generation pipeline than the real sensor, not a "
            "property of the physical process."
        ),
        "identity_gates": {
            "fix1_style_gate_vs_exp0025": detector.gate_vs_exp0025,
            "run_detector_modified": False,
        },
        "manifest": {"split_id": blocks.split_id, "membership_sha256": blocks.split_sha256},
        "ulp_distance_metric_definition": (
            "min(|v - r| for r in R), R = sorted unique TRAIN-normal raw float64 pressure "
            "values; NOT a ULP-count metric despite the inherited name; nearest-neighbour "
            "via np.searchsorted with predecessor/successor comparison; out-of-range "
            "candidates score against R's nearest edge (no extrapolation). See module "
            "docstring for the full precise definition."
        ),
        "feature_set": F2_NAMES,
        "xgb_params": XGB_PARAMS,
        "max_normal_fpr_threshold_fit": MAX_NORMAL_FPR,
        "n_bootstrap": N_BOOTSTRAP, "n_permutations": N_PERMUTATIONS,
        "per_attack": {
            k: {
                "known_val_recall_point_estimate": v["family_result"].get("val_recall_point_estimate"),
                "val_recall_bootstrap_ci95": v["family_result"].get("val_recall_bootstrap_ci95"),
                "clears_permutation_null": v["family_result"].get("clears_permutation_null"),
                "refit_reproduces_reported_val_recall": v["refit_reproduces_reported_val_recall"],
                "leave_one_run_out_fitted_model": v["leave_one_run_out_fitted_model"],
            }
            for k, v in per_attack.items()
        },
        "test_scored_once": {
            "baseline_confusion_exp0025_wired": baseline_confusion,
            "new_confusion_with_float_rule": new_confusion,
            "marginal_contribution": marginal,
            "pure_cohort_recall": pure_cohort,
        },
        "decision_rule": {
            "fpr_bar": FPR_BAR,
            "per_attack_verdicts": verdicts,
            "overall_verdict": overall_verdict,
        },
        "software": {
            "python": platform.python_version(), "numpy": version("numpy"),
            "xgboost": version("xgboost"),
        },
        "limitations": [
            "Bootstrap/permutation counts reduced (60/20) from the spec's illustrative "
            "200/50, same disclosed convention as EXP-0032, for session compute-time "
            "tractability.",
            "Leave-one-run-out pools TRAIN+VAL for training (inherited from "
            "exp0032b_ceiling_audit_corrected.leave_one_run_out; disclosed there).",
            "The rate rule is refit in-process inside FrozenCombinedWithRateDetector "
            "(not loaded from a serialized object); its exact TEST element-wise match "
            "against the frozen EXP-0025 arrays is the evidence this refit is faithful.",
            "Two separate per-attack-type XGBoost classifiers are combined by OR at "
            "inference (the rule does not know the true attack category); this mirrors "
            "how the underlying research (EXP-0032b) evaluated NMRI/CMRI separately.",
            "Pressure is the ARFF-aligned value, not a live 0x03 byte decode; register "
            "map/scale undocumented. One testbed; egress-only; measurement only.",
        ],
    }


# --------------------------------------------------------------- io

def _json_ready(value):
    if isinstance(value, Mapping):
        return {k: _json_ready(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(v) for v in value]
    if isinstance(value, (np.generic,)):
        return _json_ready(value.item())
    if isinstance(value, bool):
        return value
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def write_result_atomic(result: Mapping, path: Path = RESULT_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(_json_ready(result), indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def main() -> None:
    result = run_experiment()
    write_result_atomic(result)
    print(json.dumps(_json_ready(result), indent=2)[:8000])
    print(f"\n[result -> {RESULT_PATH}]")


if __name__ == "__main__":
    main()
