#!/usr/bin/env python3
"""VALIDATION-only independent detector variants for EXP-0009."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

import numpy as np
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

from exp0008_cadence import (
    _cohort, _labels, _matrix, binary_metrics, classifier_fingerprint,
)
from exp0008_cadence_features import (
    CadenceWindow, Mapper, PreTestArtifacts, canonical_response_type,
    prepare_pretest_artifacts,
)
from exp0009_payload import PressureArtifacts, prepare_pressure_artifacts
from features_txt import FrameRecord

SEED = 0
PROBABILITY_THRESHOLD = 0.5
THRESHOLDS = tuple(round(value, 2) for value in np.arange(0.10, 0.901, 0.05))
VARIANT_ORDER = ("EXP-0009a", "EXP-0009b", "EXP-0009c", "EXP-0009d")
FINAL_TEST_CONFIRMATION = "SCORE-EXP-0009-FROZEN-TEST-ONCE"
VALIDATION_RESULT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "experiments"
    / "exp0009_validation.json"
)
FINAL_RESULT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "experiments"
    / "exp0009_final.json"
)


@dataclass(frozen=True)
class VariantPrediction:
    name: str
    probabilities: np.ndarray
    configuration: Mapping
    fingerprint: str
    details: Mapping | None = None


def make_random_forest(*, class_weight: str | None) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators=300, class_weight=class_weight,
        random_state=SEED, n_jobs=-1,
    )


def make_smote() -> SMOTE:
    return SMOTE(sampling_strategy="auto", k_neighbors=5, random_state=SEED)


def make_xgboost(scale_pos_weight: float) -> XGBClassifier:
    return XGBClassifier(
        objective="binary:logistic", n_estimators=300,
        random_state=SEED, n_jobs=-1, eval_metric="logloss",
        scale_pos_weight=scale_pos_weight,
    )


def _semantic_fingerprint(model: object) -> str:
    if isinstance(model, RandomForestClassifier):
        return classifier_fingerprint(model)
    digest = hashlib.sha256()
    if isinstance(model, XGBClassifier):
        digest.update(json.dumps(model.get_params(), sort_keys=True).encode("utf-8"))
        digest.update(model.get_booster().save_raw(raw_format="json"))
        return digest.hexdigest()
    raise TypeError(f"unsupported model type: {type(model).__name__}")


def _cadence_data(
    artifacts: PreTestArtifacts,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    train_indices = _cohort(artifacts.train_windows)
    validation_indices = _cohort(artifacts.validation_windows)
    train_matrix = _matrix(artifacts.train_windows, artifacts.feature_names)[train_indices]
    validation_matrix = _matrix(
        artifacts.validation_windows, artifacts.feature_names,
    )[validation_indices]
    return (
        train_indices, validation_indices, train_matrix, validation_matrix,
        _labels(artifacts.train_windows, train_indices),
        _labels(artifacts.validation_windows, validation_indices),
    )


def _payload_matrix(
    windows: Sequence[CadenceWindow], indices: np.ndarray,
    payload_features: Mapping[int, Mapping[str, float]], names: Sequence[str],
) -> np.ndarray:
    return np.asarray([
        [payload_features[windows[index].bucket_index][name] for name in names]
        for index in indices
    ], dtype=float)


def run_variant_a(
    artifacts: PreTestArtifacts, pressure: PressureArtifacts,
) -> VariantPrediction | None:
    if not pressure.audit["passed"]:
        return None
    train_indices, validation_indices, x_train, x_validation, y_train, _ = _cadence_data(artifacts)
    x_train = np.column_stack((x_train, _payload_matrix(
        artifacts.train_windows, train_indices, pressure.train_features,
        pressure.feature_names,
    )))
    x_validation = np.column_stack((x_validation, _payload_matrix(
        artifacts.validation_windows, validation_indices,
        pressure.validation_features, pressure.feature_names,
    )))
    model = make_random_forest(class_weight="balanced")
    model.fit(x_train, y_train)
    return VariantPrediction(
        name="EXP-0009a", probabilities=model.predict_proba(x_validation)[:, 1],
        configuration={
            "model": "RandomForestClassifier", "n_estimators": 300,
            "class_weight": "balanced", "random_state": SEED, "n_jobs": -1,
            "features": [*artifacts.feature_names, *pressure.feature_names],
            "pressure_baselines": {
                f"0x{key:02x}": value for key, value in pressure.baselines.items()
            },
        },
        fingerprint=_semantic_fingerprint(model),
    )


def run_variant_b(artifacts: PreTestArtifacts) -> VariantPrediction:
    _, _, x_train, x_validation, y_train, _ = _cadence_data(artifacts)
    sampler = make_smote()
    resampled_x, resampled_y = sampler.fit_resample(x_train, y_train)
    model = make_random_forest(class_weight=None)
    model.fit(resampled_x, resampled_y)
    return VariantPrediction(
        name="EXP-0009b", probabilities=model.predict_proba(x_validation)[:, 1],
        configuration={
            "sampler": "SMOTE", "sampling_strategy": "auto", "k_neighbors": 5,
            "sampler_random_state": SEED, "resampled_train_rows": len(resampled_y),
            "resampled_normal": int((resampled_y == 0).sum()),
            "resampled_dos": int((resampled_y == 1).sum()),
            "model": "RandomForestClassifier", "n_estimators": 300,
            "class_weight": None, "random_state": SEED, "n_jobs": -1,
            "features": list(artifacts.feature_names),
        },
        fingerprint=_semantic_fingerprint(model),
    )


def run_variant_c(artifacts: PreTestArtifacts) -> VariantPrediction:
    _, _, x_train, x_validation, y_train, _ = _cadence_data(artifacts)
    normal, dos = int((y_train == 0).sum()), int((y_train == 1).sum())
    ratio = normal / dos
    model = make_xgboost(ratio)
    model.fit(x_train, y_train)
    return VariantPrediction(
        name="EXP-0009c", probabilities=model.predict_proba(x_validation)[:, 1],
        configuration={
            "model": "XGBClassifier", "parameters": model.get_params(),
            "scale_pos_weight_derivation": f"{normal}/{dos}",
            "features": list(artifacts.feature_names),
        },
        fingerprint=_semantic_fingerprint(model),
    )


def per_type_feature_names(response_type: int) -> tuple[str, ...]:
    prefix = f"func_{response_type:02x}_"
    return tuple(f"{prefix}{name}" for name in (
        "event_count", "iat_count", "iat_mean", "iat_std", "iat_max",
        "deviation_mean", "positive_deviation_mean", "positive_z_mean",
        "positive_z_max", "missed_cycles_sum", "missed_cycle_event_count",
        "cusum_end", "cusum_max", "cusum_alarm_count",
    ))


def combine_type_probabilities(
    probabilities: Sequence[np.ndarray], active_masks: Sequence[np.ndarray],
) -> np.ndarray:
    if not probabilities:
        return np.array([], dtype=float)
    contributions = [np.where(mask, values, 0.0) for values, mask in zip(probabilities, active_masks)]
    return np.maximum.reduce(contributions)


def run_variant_d(artifacts: PreTestArtifacts) -> VariantPrediction:
    train_indices, validation_indices, _, _, y_train, y_validation = _cadence_data(artifacts)
    probabilities = []
    active_masks = []
    detail_rows = {}
    fingerprints = {}
    configurations = {}
    for response_type in artifacts.response_types:
        names = per_type_feature_names(response_type)
        train_matrix = _matrix(artifacts.train_windows, names)[train_indices]
        validation_matrix = _matrix(artifacts.validation_windows, names)[validation_indices]
        train_active = train_matrix[:, 0] > 0
        validation_active = validation_matrix[:, 0] > 0
        if len(np.unique(y_train[train_active])) != 2:
            raise ValueError(f"type 0x{response_type:02x} active TRAIN cohort lacks both classes")
        model = make_random_forest(class_weight="balanced")
        model.fit(train_matrix[train_active], y_train[train_active])
        type_probability = np.zeros(len(validation_matrix), dtype=float)
        type_probability[validation_active] = model.predict_proba(
            validation_matrix[validation_active]
        )[:, 1]
        probabilities.append(type_probability)
        active_masks.append(validation_active)
        key = f"0x{response_type:02x}"
        detail_rows[key] = {
            "train_active_rows": int(train_active.sum()),
            "validation_active_rows": int(validation_active.sum()),
            "metrics": binary_metrics(
                y_validation[validation_active],
                (type_probability[validation_active] >= PROBABILITY_THRESHOLD).astype(int),
            ),
        }
        fingerprints[key] = _semantic_fingerprint(model)
        configurations[key] = {
            "features": list(names), "n_estimators": 300,
            "class_weight": "balanced", "random_state": SEED, "n_jobs": -1,
        }
    digest = hashlib.sha256()
    digest.update(json.dumps(fingerprints, sort_keys=True).encode("utf-8"))
    return VariantPrediction(
        name="EXP-0009d",
        probabilities=combine_type_probabilities(probabilities, active_masks),
        configuration={
            "models": configurations, "inactive_probability": 0.0,
            "combiner": "maximum active-type probability",
        },
        fingerprint=digest.hexdigest(), details=MappingProxy(fingerprints, detail_rows),
    )


class MappingProxy(dict):
    """JSON-friendly immutable-by-convention detail bundle."""

    def __init__(self, fingerprints: Mapping, rows: Mapping):
        super().__init__(model_fingerprints=dict(fingerprints), active_type_rows=dict(rows))


def evaluate_probabilities(
    labels: np.ndarray, probabilities: np.ndarray, threshold: float,
) -> dict:
    return binary_metrics(labels, (probabilities >= threshold).astype(int))


def select_variant(metrics: Mapping[str, Mapping]) -> str:
    eligible = [name for name in VARIANT_ORDER if name in metrics]
    if not eligible:
        raise ValueError("no eligible EXP-0009a-d variant")
    order = {name: index for index, name in enumerate(VARIANT_ORDER)}
    return max(eligible, key=lambda name: (
        metrics[name]["f1"], metrics[name]["recall"], metrics[name]["precision"],
        -order[name],
    ))


def threshold_sweep(labels: np.ndarray, probabilities: np.ndarray) -> list[dict]:
    return [
        {"threshold": threshold, **evaluate_probabilities(labels, probabilities, threshold)}
        for threshold in THRESHOLDS
    ]


def recommend_threshold(rows: Sequence[Mapping]) -> tuple[Mapping, str]:
    feasible = [row for row in rows if row["precision"] >= 0.50]
    if feasible:
        return max(feasible, key=lambda row: (
            row["recall"], row["f1"], row["precision"], row["threshold"],
        )), "maximum recall subject to precision >= 0.50"
    return max(rows, key=lambda row: (
        row["f1"], row["recall"], row["precision"], row["threshold"],
    )), "fallback maximum F1 because no threshold reached precision >= 0.50"


def _versions() -> dict[str, str]:
    return {
        "python": platform.python_version(), "numpy": np.__version__,
        "scikit-learn": version("scikit-learn"),
        "imbalanced-learn": version("imbalanced-learn"),
        "xgboost": version("xgboost"),
    }


def prepare_validation_study(
    records: Iterable[FrameRecord] | None = None,
    arff_rows: Iterable[Sequence[str]] | None = None,
    mapper: Mapper = canonical_response_type,
) -> tuple[dict, PreTestArtifacts, Mapping[str, VariantPrediction]]:
    """Run TRAIN fits and VALIDATION selection while retaining no TEST artifacts."""
    materialized = None if records is None else tuple(records)
    artifacts = prepare_pretest_artifacts(materialized)
    pressure = prepare_pressure_artifacts(
        artifacts.inputs.train, artifacts.inputs.validation, artifacts.type_map,
        records=materialized, arff_rows=arff_rows, mapper=mapper,
    )
    variants: dict[str, VariantPrediction] = {}
    variant_a = run_variant_a(artifacts, pressure)
    if variant_a is not None:
        variants[variant_a.name] = variant_a
    for runner in (run_variant_b, run_variant_c, run_variant_d):
        variant = runner(artifacts)
        variants[variant.name] = variant
    validation_indices = _cohort(artifacts.validation_windows)
    labels = _labels(artifacts.validation_windows, validation_indices)
    fixed_metrics = {
        name: evaluate_probabilities(labels, variant.probabilities, PROBABILITY_THRESHOLD)
        for name, variant in variants.items()
    }
    winner = select_variant(fixed_metrics)
    sweep = threshold_sweep(labels, variants[winner].probabilities)
    recommendation, rule = recommend_threshold(sweep)
    variant_rows = {}
    for name in VARIANT_ORDER:
        if name in variants:
            prediction = variants[name]
            variant_rows[name] = {
                "status": "VALIDATED — VALIDATION ONLY", "threshold": 0.5,
                "metrics": fixed_metrics[name], "configuration": prediction.configuration,
                "semantic_fingerprint_sha256": prediction.fingerprint,
                **({"details": prediction.details} if prediction.details else {}),
            }
        else:
            variant_rows[name] = {
                "status": pressure.audit["status"],
                "reasons": list(pressure.audit["reasons"]), "eligible_for_0009e": False,
            }
    result = {
        "status": "VALIDATED — VALIDATION ONLY; TEST NOT RUN",
        "experiment": "EXP-0009", "environment": _versions(),
        "scope": {
            "direction": "egress only", "destination": 1,
            "cohort": "DoS-containing versus pure-Normal five-second windows",
            "total_egress_frames": artifacts.inputs.total_egress_frames,
            "total_emitted_windows": artifacts.inputs.total_emitted_windows,
        },
        "split_window_counts": {
            "train": artifacts.inputs.train_window_count,
            "validation": artifacts.inputs.validation_window_count,
            "test_unopened": artifacts.inputs.test_window_count,
        },
        "validation_counts": {
            "cohort": len(labels), "normal": int((labels == 0).sum()),
            "dos": int((labels == 1).sum()),
        },
        "inherited_integrity": {
            "response_type_audit": dict(artifacts.audit),
            "canonical_mapper": f"{mapper.__module__}.{mapper.__name__}",
            "exp0008_files_modified": False,
        },
        "payload_provenance": {
            "field": "pressure measurement", "arff_column_index_zero_based": 13,
            "allowed_arff_direction": "command response == 0",
            "aligned_txt_direction": "destination == 1",
            "txt_sha256": pressure.aligned.txt_sha256,
            "arff_sha256": pressure.aligned.arff_sha256,
            "raw_txt_independent_pressure_decode": False,
            "forbidden_command_payload_fields_used": [],
            "audit": dict(pressure.audit),
            "feature_names": list(pressure.feature_names),
        },
        "variants": variant_rows,
        "EXP-0009e": {
            "selection_basis": "VALIDATION F1, recall, precision, fixed a-to-d order",
            "selected_variant": winner, "threshold_curve": sweep,
            "recommendation_rule": rule,
            "recommended_threshold": recommendation["threshold"],
            "recommended_validation_metrics": {
                key: value for key, value in recommendation.items() if key != "threshold"
            },
            "frozen_proposed_configuration": {
                "variant": winner, "threshold": recommendation["threshold"],
                "configuration": variants[winner].configuration,
                "semantic_fingerprint_sha256": variants[winner].fingerprint,
            },
        },
        "test_metrics": {"status": "NOT RUN"},
        "limitations": [
            "ARFF pressure is row-aligned but is not independently decoded by the TXT parser.",
            "Response type is an egress-visible proxy for an unseen query type.",
            "The labelled attack is not established as a classic volumetric flood.",
            "Variant and threshold selection reuse VALIDATION and require one untouched TEST check.",
            "One labelled testbed cannot establish universal DoS detectability.",
        ],
    }
    return result, artifacts, variants


def score_frozen_test_once(
    confirmation: str, frozen_validation: Mapping,
    records: Iterable[FrameRecord] | None = None,
) -> dict:
    """Guard the future TEST boundary; implementation follows only after sign-off."""
    if confirmation != FINAL_TEST_CONFIRMATION:
        raise PermissionError("EXP-0009 TEST requires the exact explicit confirmation token")
    raise RuntimeError(
        "EXP-0009 frozen TEST scoring is intentionally not implemented before sign-off"
    )


def write_result_atomic(result: Mapping, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--score-frozen-test", action="store_true")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if args.score_frozen_test:
        raise PermissionError("EXP-0009 TEST is not authorized; run VALIDATION only")
    result, _, _ = prepare_validation_study()
    write_result_atomic(result, VALIDATION_RESULT_PATH)
    print(json.dumps(result, indent=2))
    print(f"\n[result -> {VALIDATION_RESULT_PATH}]")


if __name__ == "__main__":
    main()
