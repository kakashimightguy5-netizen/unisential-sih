#!/usr/bin/env python3
"""Frozen TRAIN/VALIDATION-only follow-up variants for EXP-0011."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

import numpy as np
from imblearn.over_sampling import ADASYN, BorderlineSMOTE

from exp0008_cadence import (
    _cohort, _labels, _matrix, _test_block, binary_metrics,
    classifier_fingerprint,
)
from exp0008_cadence_features import (
    CadenceWindow, Mapper, PreTestArtifacts, build_scoring_windows,
    canonical_response_type, prepare_pretest_artifacts,
)
from exp0009_variants import (
    THRESHOLDS, VariantPrediction, evaluate_probabilities, make_random_forest,
    make_smote, make_xgboost, recommend_threshold, threshold_sweep,
)
from exp0011_payload_diagnostic import (
    Payload03Artifacts, prepare_03_payload_artifacts,
)
from features_txt import FrameRecord

RESULT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "experiments"
    / "exp0011_validation.json"
)
FINAL_RESULT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "experiments"
    / "exp0011b_final.json"
)
FINAL_TEST_CONFIRMATION = "SCORE-EXP-0011B-FROZEN-TEST-ONCE"
FINAL_VARIANT = "EXP-0011b-borderline-smote"
FINAL_THRESHOLD = 0.50
FINAL_FINGERPRINT = (
    "bb89557b34a1ff3850ae06a3e8151d70dad9f215837f5c0d5216e1a5b0f9cc40"
)
RF_GRID = tuple(
    (max_depth, min_samples_leaf)
    for max_depth in (None, 10, 20) for min_samples_leaf in (1, 2, 5)
)
def grid_candidate_name(
    max_depth: int | None, min_samples_leaf: int,
) -> str:
    depth_name = "none" if max_depth is None else str(max_depth)
    return f"EXP-0011c-depth-{depth_name}-leaf-{min_samples_leaf}"


CANDIDATE_ORDER = (
    "EXP-0009b", "EXP-0011a", "EXP-0011b-borderline-smote",
    "EXP-0011b-adasyn",
    *(grid_candidate_name(depth, leaf) for depth, leaf in RF_GRID),
    "EXP-0011d",
)


@dataclass(frozen=True)
class DataMatrices:
    train_indices: np.ndarray
    validation_indices: np.ndarray
    x_train: np.ndarray
    x_validation: np.ndarray
    y_train: np.ndarray
    y_validation: np.ndarray


def prepare_matrices(artifacts: PreTestArtifacts) -> DataMatrices:
    train_indices = _cohort(artifacts.train_windows)
    validation_indices = _cohort(artifacts.validation_windows)
    return DataMatrices(
        train_indices=train_indices, validation_indices=validation_indices,
        x_train=_matrix(artifacts.train_windows, artifacts.feature_names)[train_indices],
        x_validation=_matrix(
            artifacts.validation_windows, artifacts.feature_names,
        )[validation_indices],
        y_train=_labels(artifacts.train_windows, train_indices),
        y_validation=_labels(artifacts.validation_windows, validation_indices),
    )


def _payload_matrix(
    windows: Sequence[CadenceWindow], indices: np.ndarray,
    payload: Mapping[int, Mapping[str, float]], names: Sequence[str],
) -> np.ndarray:
    return np.asarray([
        [payload[windows[index].bucket_index][name] for name in names]
        for index in indices
    ], dtype=float)


def _rf_fingerprint(model, extra: Mapping | None = None) -> str:
    if not extra:
        return classifier_fingerprint(model)
    digest = hashlib.sha256()
    digest.update(classifier_fingerprint(model).encode("ascii"))
    digest.update(json.dumps(extra, sort_keys=True).encode("utf-8"))
    return digest.hexdigest()


def _fit_rf(
    x_train: np.ndarray, y_train: np.ndarray, x_validation: np.ndarray,
    *, max_depth: int | None = None, min_samples_leaf: int = 1,
):
    model = make_random_forest(class_weight=None)
    model.set_params(max_depth=max_depth, min_samples_leaf=min_samples_leaf)
    model.fit(x_train, y_train)
    return model, model.predict_proba(x_validation)[:, 1]


def _resample_fit(
    data: DataMatrices, sampler, name: str,
) -> VariantPrediction:
    x_resampled, y_resampled = sampler.fit_resample(data.x_train, data.y_train)
    model, probabilities = _fit_rf(
        x_resampled, y_resampled, data.x_validation,
    )
    params = sampler.get_params()
    return VariantPrediction(
        name=name, probabilities=probabilities,
        configuration={
            "sampler": type(sampler).__name__,
            "sampler_parameters": params,
            "resampled_rows": len(y_resampled),
            "resampled_normal": int((y_resampled == 0).sum()),
            "resampled_dos": int((y_resampled == 1).sum()),
            "model": "RandomForestClassifier", "n_estimators": 300,
            "class_weight": None, "random_state": 0, "n_jobs": -1,
            "max_depth": None, "min_samples_leaf": 1,
        },
        fingerprint=_rf_fingerprint(model, {"sampler": type(sampler).__name__, **params}),
    )


def run_baseline(data: DataMatrices) -> VariantPrediction:
    return _resample_fit(data, make_smote(), "EXP-0009b")


def fit_final_0011b(data: DataMatrices):
    sampler = BorderlineSMOTE(
        sampling_strategy="auto", k_neighbors=5, random_state=0,
    )
    x_resampled, y_resampled = sampler.fit_resample(data.x_train, data.y_train)
    model = make_random_forest(class_weight=None)
    model.set_params(max_depth=None, min_samples_leaf=1)
    model.fit(x_resampled, y_resampled)
    sampler_parameters = sampler.get_params()
    configuration = {
        "sampler": type(sampler).__name__,
        "sampler_parameters": sampler_parameters,
        "resampled_rows": len(y_resampled),
        "resampled_normal": int((y_resampled == 0).sum()),
        "resampled_dos": int((y_resampled == 1).sum()),
        "model": "RandomForestClassifier", "n_estimators": 300,
        "class_weight": None, "random_state": 0, "n_jobs": -1,
        "max_depth": None, "min_samples_leaf": 1,
    }
    fingerprint = _rf_fingerprint(model, {
        "sampler": type(sampler).__name__, **sampler_parameters,
    })
    return model, configuration, fingerprint


def assert_final_0011b(
    configuration: Mapping, fingerprint: str,
) -> None:
    expected_sampler = {
        "sampling_strategy": "auto", "random_state": 0,
        "k_neighbors": 5, "m_neighbors": 10, "kind": "borderline-1",
    }
    actual_sampler = configuration["sampler_parameters"]
    if configuration["sampler"] != "BorderlineSMOTE" or any(
        actual_sampler.get(key) != value for key, value in expected_sampler.items()
    ):
        raise RuntimeError("EXP-0011b frozen Borderline-SMOTE configuration mismatch")
    expected_model = {
        "model": "RandomForestClassifier", "n_estimators": 300,
        "class_weight": None, "random_state": 0, "n_jobs": -1,
        "max_depth": None, "min_samples_leaf": 1,
    }
    if any(configuration.get(key) != value for key, value in expected_model.items()):
        raise RuntimeError("EXP-0011b frozen Random Forest configuration mismatch")
    if fingerprint != FINAL_FINGERPRINT:
        raise RuntimeError(
            "EXP-0011b semantic fingerprint mismatch before frozen TEST"
        )


def run_0011a(
    artifacts: PreTestArtifacts, data: DataMatrices, payload: Payload03Artifacts,
) -> VariantPrediction | None:
    if payload.baseline is None:
        return None
    x_train = np.column_stack((data.x_train, _payload_matrix(
        artifacts.train_windows, data.train_indices, payload.train_features,
        payload.feature_names,
    )))
    x_validation = np.column_stack((data.x_validation, _payload_matrix(
        artifacts.validation_windows, data.validation_indices,
        payload.validation_features, payload.feature_names,
    )))
    sampler = make_smote()
    x_resampled, y_resampled = sampler.fit_resample(x_train, data.y_train)
    model, probabilities = _fit_rf(x_resampled, y_resampled, x_validation)
    return VariantPrediction(
        name="EXP-0011a", probabilities=probabilities,
        configuration={
            "diagnosis": payload.diagnosis.status,
            "pressure_type": "0x03", "pressure_baseline": payload.baseline,
            "pressure_features": list(payload.feature_names),
            "missing_numeric_placeholder": 0.0,
            "availability_flag": "func_03_pressure_available",
            "0x10_pressure_features": [],
            "sampler": "SMOTE", "sampling_strategy": "auto",
            "k_neighbors": 5, "sampler_random_state": 0,
            "resampled_rows": len(y_resampled),
            "model": "RandomForestClassifier", "n_estimators": 300,
            "class_weight": None, "random_state": 0, "n_jobs": -1,
        },
        fingerprint=_rf_fingerprint(model, {
            "variant": "EXP-0011a", "baseline": payload.baseline,
        }),
    )


def run_0011b(data: DataMatrices) -> dict[str, VariantPrediction | Mapping]:
    samplers = (
        ("EXP-0011b-borderline-smote", BorderlineSMOTE(
            sampling_strategy="auto", k_neighbors=5, random_state=0,
        )),
        ("EXP-0011b-adasyn", ADASYN(
            sampling_strategy="auto", n_neighbors=5, random_state=0,
        )),
    )
    output: dict[str, VariantPrediction | Mapping] = {}
    for name, sampler in samplers:
        try:
            output[name] = _resample_fit(data, sampler, name)
        except ValueError as error:
            output[name] = {"status": "STOPPED — RESAMPLER ERROR", "reason": str(error)}
    return output


def run_0011c(data: DataMatrices) -> dict[str, VariantPrediction]:
    sampler = make_smote()
    x_resampled, y_resampled = sampler.fit_resample(data.x_train, data.y_train)
    output = {}
    for max_depth, min_samples_leaf in RF_GRID:
        name = grid_candidate_name(max_depth, min_samples_leaf)
        model, probabilities = _fit_rf(
            x_resampled, y_resampled, data.x_validation,
            max_depth=max_depth, min_samples_leaf=min_samples_leaf,
        )
        output[name] = VariantPrediction(
            name=name, probabilities=probabilities,
            configuration={
                "sampler": "SMOTE", "sampling_strategy": "auto",
                "k_neighbors": 5, "sampler_random_state": 0,
                "resampled_rows": len(y_resampled),
                "model": "RandomForestClassifier", "n_estimators": 300,
                "class_weight": None, "random_state": 0, "n_jobs": -1,
                "max_depth": max_depth, "min_samples_leaf": min_samples_leaf,
            },
            fingerprint=_rf_fingerprint(model, {
                "max_depth": max_depth, "min_samples_leaf": min_samples_leaf,
            }),
        )
    return output


def xgboost_fingerprint(model) -> str:
    digest = hashlib.sha256()
    digest.update(json.dumps(model.get_params(), sort_keys=True).encode("utf-8"))
    digest.update(model.get_booster().save_raw(raw_format="json"))
    return digest.hexdigest()


def run_0011d(
    data: DataMatrices, baseline: VariantPrediction,
) -> VariantPrediction:
    normal = int((data.y_train == 0).sum())
    dos = int((data.y_train == 1).sum())
    model = make_xgboost(normal / dos)
    model.fit(data.x_train, data.y_train)
    xgb_probabilities = model.predict_proba(data.x_validation)[:, 1]
    probabilities = (baseline.probabilities + xgb_probabilities) / 2.0
    digest = hashlib.sha256()
    digest.update(baseline.fingerprint.encode("ascii"))
    digest.update(xgboost_fingerprint(model).encode("ascii"))
    digest.update(b"equal-weights-0.5-0.5")
    return VariantPrediction(
        name="EXP-0011d", probabilities=probabilities,
        configuration={
            "combiner": "arithmetic mean", "rf_weight": 0.5,
            "xgboost_weight": 0.5,
            "rf_configuration": baseline.configuration,
            "xgboost_parameters": model.get_params(),
            "scale_pos_weight_derivation": f"{normal}/{dos}",
        },
        fingerprint=digest.hexdigest(),
        details={"xgboost_semantic_fingerprint_sha256": xgboost_fingerprint(model)},
    )


def selected_point(labels: np.ndarray, probabilities: np.ndarray) -> tuple[list[dict], Mapping, str]:
    curve = threshold_sweep(labels, probabilities)
    point, rule = recommend_threshold(curve)
    return curve, point, rule


def rank_candidates(points: Mapping[str, Mapping]) -> str:
    order = {name: index for index, name in enumerate(CANDIDATE_ORDER)}
    return max(points, key=lambda name: (
        points[name]["recall"], points[name]["f1"], points[name]["precision"],
        -order.get(name, len(order)),
    ))


def report_threshold_curves(
    curves: Mapping[str, Sequence[Mapping]], grid_winner: str,
) -> dict[str, Sequence[Mapping]]:
    return {
        name: curve for name, curve in curves.items()
        if not name.startswith("EXP-0011c-") or name == grid_winner
    }


def pareto_comparison(
    rf_curve: Sequence[Mapping], ensemble_curve: Sequence[Mapping],
) -> dict:
    def dominates(left: Mapping, right: Mapping) -> bool:
        return (
            left["precision"] >= right["precision"]
            and left["recall"] >= right["recall"]
            and (
                left["precision"] > right["precision"]
                or left["recall"] > right["recall"]
            )
        )

    ensemble_over_rf = [
        {"ensemble_threshold": left["threshold"], "rf_threshold": right["threshold"]}
        for left in ensemble_curve for right in rf_curve if dominates(left, right)
    ]
    rf_over_ensemble = [
        {"rf_threshold": left["threshold"], "ensemble_threshold": right["threshold"]}
        for left in rf_curve for right in ensemble_curve if dominates(left, right)
    ]
    return {
        "ensemble_dominates_any_rf_point": bool(ensemble_over_rf),
        "rf_dominates_any_ensemble_point": bool(rf_over_ensemble),
        "ensemble_dominance_pairs": ensemble_over_rf,
        "rf_dominance_pairs": rf_over_ensemble,
    }


def _candidate_row(
    labels: np.ndarray, prediction: VariantPrediction,
) -> tuple[dict, list[dict], Mapping]:
    curve, point, rule = selected_point(labels, prediction.probabilities)
    at_060 = evaluate_probabilities(labels, prediction.probabilities, 0.60)
    return ({
        "status": "VALIDATED — VALIDATION ONLY",
        "selected_threshold": point["threshold"],
        "selected_metrics": {key: value for key, value in point.items() if key != "threshold"},
        "selection_rule": rule, "metrics_at_0.60": at_060,
        "configuration": prediction.configuration,
        "semantic_fingerprint_sha256": prediction.fingerprint,
        **({"details": prediction.details} if prediction.details else {}),
    }, curve, point)


def prepare_validation_study(
    records: Iterable[FrameRecord] | None = None,
    arff_rows: Iterable[Sequence[str]] | None = None,
    mapper: Mapper = canonical_response_type,
) -> tuple[dict, Mapping[str, VariantPrediction]]:
    """Run EXP-0011 on TRAIN/VALIDATION while retaining no TEST artifacts."""
    materialized = None if records is None else tuple(records)
    artifacts = prepare_pretest_artifacts(materialized)
    data = prepare_matrices(artifacts)
    payload = prepare_03_payload_artifacts(
        artifacts.inputs.train, artifacts.inputs.validation, artifacts.type_map,
        records=materialized, arff_rows=arff_rows, mapper=mapper,
    )
    predictions: dict[str, VariantPrediction] = {}
    baseline = run_baseline(data)
    predictions[baseline.name] = baseline
    candidate_a = run_0011a(artifacts, data, payload)
    if candidate_a is not None:
        predictions[candidate_a.name] = candidate_a
    stopped: dict[str, Mapping] = {}
    for name, candidate in run_0011b(data).items():
        if isinstance(candidate, VariantPrediction):
            predictions[name] = candidate
        else:
            stopped[name] = candidate
    predictions.update(run_0011c(data))
    ensemble = run_0011d(data, baseline)
    predictions[ensemble.name] = ensemble

    rows, curves, points = {}, {}, {}
    for name, prediction in predictions.items():
        rows[name], curves[name], points[name] = _candidate_row(
            data.y_validation, prediction,
        )
    for name, stopped_row in stopped.items():
        rows[name] = dict(stopped_row)
    if candidate_a is None:
        rows["EXP-0011a"] = {
            "status": payload.diagnosis.status, "reason": payload.diagnosis.reason,
        }
    grid_names = [grid_candidate_name(depth, leaf) for depth, leaf in RF_GRID]
    grid_winner = rank_candidates({name: points[name] for name in grid_names})
    final_winner = rank_candidates(points)
    result = {
        "status": "VALIDATED — VALIDATION ONLY; TEST NOT RUN",
        "experiment": "EXP-0011",
        "scope": {
            "direction": "egress only", "destination": 1,
            "total_egress_frames": artifacts.inputs.total_egress_frames,
            "total_emitted_windows": artifacts.inputs.total_emitted_windows,
            "split_window_counts": {
                "train": artifacts.inputs.train_window_count,
                "validation": artifacts.inputs.validation_window_count,
                "test_unopened": artifacts.inputs.test_window_count,
            },
            "validation_cohort": {
                "total": len(data.y_validation),
                "normal": int((data.y_validation == 0).sum()),
                "dos": int((data.y_validation == 1).sum()),
            },
        },
        "integrity": {
            "canonical_mapper": f"{mapper.__module__}.{mapper.__name__}",
            "original_cadence_feature_count": len(artifacts.feature_names),
            "test_materialized": False,
        },
        "EXP-0011a_diagnosis": {
            "status": payload.diagnosis.status,
            "reason": payload.diagnosis.reason,
            "protocol": payload.diagnosis.protocol,
            "shape_check": payload.diagnosis.shape_check,
            "pressure_counts": payload.diagnosis.pressure_counts,
            "0x03_train_normal_baseline": payload.baseline,
        },
        "candidates": rows,
        "threshold_curves": report_threshold_curves(curves, grid_winner),
        "EXP-0011c": {
            "preregistered_grid": [
                {"max_depth": depth, "min_samples_leaf": leaf}
                for depth, leaf in RF_GRID
            ],
            "winner": grid_winner,
            "all_selected_points": {
                name: {"threshold": points[name]["threshold"], **rows[name]["selected_metrics"]}
                for name in grid_names
            },
        },
        "EXP-0011d_pareto": pareto_comparison(
            curves["EXP-0009b"], curves["EXP-0011d"],
        ),
        "final_comparison": {
            name: {"threshold": point["threshold"], **rows[name]["selected_metrics"]}
            for name, point in points.items()
            if not name.startswith("EXP-0011c-") or name == grid_winner
        },
        "recommendation": {
            "configuration": final_winner,
            "meaningfully_beats_EXP-0009b": final_winner != "EXP-0009b",
            "selected_threshold": points[final_winner]["threshold"],
            "validation_metrics": rows[final_winner]["selected_metrics"],
            "rule": "precision >= 0.50; maximize recall, then F1, precision; incumbent-first exact ties",
        },
        "test_metrics": {"status": "NOT RUN"},
        "limitations": [
            "ARFF pressure is aligned but is not independently decoded by the TXT parser.",
            "The 0x03 availability flag may expose protocol schedule/presence information.",
            "Repeated candidate and threshold comparisons reuse one VALIDATION block.",
            "Response type is an egress-visible proxy for an unseen query.",
            "The labelled attack is not established as a classic volumetric flood.",
            "One labelled testbed cannot establish universal DoS detectability.",
        ],
    }
    return result, MappingProxyLike(predictions)


class MappingProxyLike(dict):
    """Read-only-by-convention return bundle for tests and diagnostics."""


def score_frozen_test_once(
    confirmation: str, records: Iterable[FrameRecord] | None = None,
) -> dict:
    """Fit the authorized EXP-0011b configuration, then score TEST once."""
    if confirmation != FINAL_TEST_CONFIRMATION:
        raise PermissionError(
            "EXP-0011b frozen TEST requires the exact explicit confirmation token"
        )
    materialized = None if records is None else tuple(records)
    artifacts = prepare_pretest_artifacts(materialized)
    data = prepare_matrices(artifacts)
    model, configuration, fingerprint = fit_final_0011b(data)
    assert_final_0011b(configuration, fingerprint)

    test = _test_block(materialized)
    test_windows = build_scoring_windows(
        test, artifacts.type_map, artifacts.baselines, artifacts.thresholds,
    )
    cohort = _cohort(test_windows)
    labels = _labels(test_windows, cohort)
    matrix = _matrix(test_windows, artifacts.feature_names)[cohort]
    probabilities = model.predict_proba(matrix)[:, 1]
    predictions = (probabilities >= FINAL_THRESHOLD).astype(int)
    metrics = binary_metrics(labels, predictions)
    return {
        "status": "VALIDATED — ONE FROZEN TEST PASS; NO RERUN",
        "experiment": "EXP-0011b",
        "selection": {
            "status": "HUMAN DEPLOYMENT-SUITABILITY OVERRIDE AFTER VALIDATION",
            "mechanical_rule_winner_not_selected": "EXP-0011a",
            "final_configuration": FINAL_VARIANT,
            "reason": (
                "0011a gained 6 VALIDATION true positives at the cost of 77 false "
                "positives and retained unresolved availability-feature leakage risk"
            ),
        },
        "scope": {
            "direction": "egress only", "destination": 1,
            "cohort": "DoS-containing versus pure-Normal five-second windows",
            "total_egress_frames": artifacts.inputs.total_egress_frames,
            "total_emitted_windows": artifacts.inputs.total_emitted_windows,
            "split_window_counts": {
                "train": artifacts.inputs.train_window_count,
                "validation": artifacts.inputs.validation_window_count,
                "test": len(test_windows),
            },
        },
        "test_counts": {
            "windows": len(test_windows), "cohort": len(labels),
            "normal": int((labels == 0).sum()),
            "dos": int((labels == 1).sum()),
            "excluded_other_attack": len(test_windows) - len(labels),
        },
        "configuration": {
            **configuration,
            "probability_threshold": FINAL_THRESHOLD,
            "feature_count": len(artifacts.feature_names),
            "features": list(artifacts.feature_names),
            "payload_features": [],
        },
        "semantic_fingerprint_sha256": fingerprint,
        "test_metrics": metrics,
        "comparison_context": {
            "EXP-0004": {
                "scope": "egress-only; different 136 dominant-DoS category row",
                "precision": None, "recall_or_flag_rate": 0.0, "f1": None,
                "fpr": 0.007489,
            },
            "EXP-0005b": {
                "scope": "OUT OF SCOPE — bidirectional; 193 DoS versus 4,931 Normal",
                "precision": 0.6302521008403361,
                "recall": 0.38860103626943004,
                "f1": 0.4807692307692308,
                "fpr": 0.008923139322652606,
                "tn": 4887, "fp": 44, "fn": 118, "tp": 75,
            },
            "EXP-0008-detector-a": {
                "scope": "egress-only; same 193 DoS versus 4,807 Normal TEST cohort",
                "precision": 0.0, "recall": 0.0, "f1": 0.0, "fpr": 0.0,
                "tn": 4807, "fp": 0, "fn": 193, "tp": 0,
            },
            "EXP-0008-detector-b": {
                "scope": "egress-only; same 193 DoS versus 4,807 Normal TEST cohort",
                "precision": 0.6341463414634146,
                "recall": 0.2694300518134715,
                "f1": 0.3781818181818182,
                "fpr": 0.006240898689411275,
                "tn": 4777, "fp": 30, "fn": 141, "tp": 52,
            },
            "EXP-0009b": {
                "scope": "VALIDATION ONLY; no frozen TEST score",
                "threshold": 0.60, "precision": 0.9298245614035088,
                "recall": 0.5221674876847291, "f1": 0.668769716088328,
                "fpr": 0.0016488046166529267,
                "tn": 4844, "fp": 8, "fn": 97, "tp": 106,
            },
        },
        "limitations": [
            "EXP-0004 and EXP-0005b use different cohorts or observation boundaries.",
            "EXP-0009b has VALIDATION metrics only, not a frozen TEST score.",
            "The labelled attack is not established as a classic volumetric flood.",
            "One labelled testbed cannot establish universal DoS detectability.",
        ],
    }


def _json_ready(value):
    if isinstance(value, Mapping):
        return {key: _json_ready(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_ready(item) for item in value]
    if isinstance(value, np.generic):
        return _json_ready(value.item())
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def write_result_atomic(result: Mapping, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(_json_ready(result), indent=2) + "\n", encoding="utf-8",
    )
    os.replace(temporary, path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--score-frozen-test", action="store_true")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if args.score_frozen_test:
        result = score_frozen_test_once(args.confirm)
        path = FINAL_RESULT_PATH
    else:
        if args.confirm:
            parser.error("--confirm is valid only with --score-frozen-test")
        result, _ = prepare_validation_study()
        path = RESULT_PATH
    write_result_atomic(result, path)
    print(json.dumps(_json_ready(result), indent=2))
    print(f"\n[result -> {path}]")


if __name__ == "__main__":
    main()
