"""Synthetic resampling, grid, ensemble, and TEST-blindness proofs for EXP-0011."""
from dataclasses import replace

import numpy as np
import pytest

import exp0008_cadence_features as cadence
import exp0011_validation as experiment
from exp0009_variants import VariantPrediction
from features_txt import FrameRecord


def record(index, timestamp, *, function, category):
    length, byte_count = {3: (23, 18), 16: (8, -1)}[function]
    return FrameRecord(
        record_index=index, frame_id=index, address=4, function_code=function,
        frame_len_bytes=length, is_request=0, start_register=-1, quantity=-1,
        byte_count=byte_count, length_anomaly=0, rare_function_code=0, crc_ok=0,
        interarrival_seconds=0.0, message_entropy_bits_per_byte=0.0,
        categorized_attack=category, specific_attack=0, source=3, destination=1,
        timestamp=timestamp,
    )


def synthetic_split():
    train, validation, _ = cadence._contiguous_blocks(30)
    return cadence.PreTestSplit(
        "synthetic-pretest-v1", "synthetic",
        tuple(map(int, train)), tuple(map(int, validation)), (17, 18),
    )


def capture():
    rows = []
    index = 1
    for bucket in range(30):
        category = 6 if bucket % 4 == 3 else 0
        for offset, function in ((0.1, 3), (0.2, 16), (2.1, 3), (2.2, 16)):
            rows.append(record(index, bucket * 5 + offset, function=function, category=category))
            index += 1
    return tuple(rows)


def arff(item, pressure):
    return (
        "4", str(item.function_code), str(item.frame_len_bytes),
        *("FORBIDDEN" for _ in range(10)), pressure, "CRC", "0",
        str(item.timestamp), "0", str(item.categorized_attack), "0",
    )


def artifacts(monkeypatch):
    monkeypatch.setattr(cadence, "AUDIT_MIN_FRAMES", 1)
    monkeypatch.setattr(cadence, "AUDIT_MIN_IATS", 1)
    monkeypatch.setattr(cadence, "AUDIT_MIN_WINDOWS", 1)
    return cadence.prepare_pretest_artifacts(capture(), split=synthetic_split())


def test_sampler_configs_grid_and_candidate_order_are_frozen():
    assert experiment.RF_GRID == (
        (None, 1), (None, 2), (None, 5),
        (10, 1), (10, 2), (10, 5),
        (20, 1), (20, 2), (20, 5),
    )
    from imblearn.over_sampling import ADASYN, BorderlineSMOTE
    borderline = BorderlineSMOTE(sampling_strategy="auto", k_neighbors=5, random_state=0)
    adasyn = ADASYN(sampling_strategy="auto", n_neighbors=5, random_state=0)
    assert borderline.k_neighbors == 5 and borderline.random_state == 0
    assert adasyn.n_neighbors == 5 and adasyn.random_state == 0
    assert experiment.CANDIDATE_ORDER[0] == "EXP-0009b"
    assert experiment.CANDIDATE_ORDER[4:13] == tuple(
        experiment.grid_candidate_name(depth, leaf)
        for depth, leaf in experiment.RF_GRID
    )
    assert "EXP-0011c-depth-none-leaf-1" in experiment.CANDIDATE_ORDER
    assert not any("depth-None" in name for name in experiment.CANDIDATE_ORDER)


def test_alternative_resamplers_receive_train_only_and_validation_is_unchanged(monkeypatch):
    data = experiment.prepare_matrices(artifacts(monkeypatch))
    before = data.x_validation.tobytes()
    seen = []

    class SpySampler:
        def __init__(self, name):
            self.name = name

        def fit_resample(self, matrix, labels):
            seen.append((self.name, len(matrix)))
            return matrix, labels

        def get_params(self):
            return {"name": self.name}

    monkeypatch.setattr(experiment, "BorderlineSMOTE", lambda **kwargs: SpySampler("borderline"))
    monkeypatch.setattr(experiment, "ADASYN", lambda **kwargs: SpySampler("adasyn"))
    monkeypatch.setattr(experiment, "_fit_rf", lambda x, y, validation, **kwargs: (
        object(), np.zeros(len(validation)),
    ))
    monkeypatch.setattr(experiment, "_rf_fingerprint", lambda model, extra=None: "fingerprint")
    results = experiment.run_0011b(data)
    assert seen == [("borderline", len(data.x_train)), ("adasyn", len(data.x_train))]
    assert all(isinstance(item, VariantPrediction) for item in results.values())
    assert data.x_validation.tobytes() == before


def test_grid_runs_all_nine_on_one_train_resample_with_frozen_parameters(monkeypatch):
    data = experiment.prepare_matrices(artifacts(monkeypatch))
    calls = []

    class SpySMOTE:
        def fit_resample(self, matrix, labels):
            calls.append(("resample", len(matrix)))
            return matrix, labels

    def spy_fit(matrix, labels, validation, **parameters):
        calls.append((parameters["max_depth"], parameters["min_samples_leaf"], len(matrix)))
        return object(), np.zeros(len(validation))

    monkeypatch.setattr(experiment, "make_smote", lambda: SpySMOTE())
    monkeypatch.setattr(experiment, "_fit_rf", spy_fit)
    monkeypatch.setattr(experiment, "_rf_fingerprint", lambda model, extra=None: "fingerprint")
    output = experiment.run_0011c(data)
    assert len(output) == 9
    assert calls[0] == ("resample", len(data.x_train))
    assert [(item[0], item[1]) for item in calls[1:]] == list(experiment.RF_GRID)
    assert all(call[2] == len(data.x_train) for call in calls[1:])


def test_report_retains_only_grid_winner_full_curve():
    curves = {
        "EXP-0009b": ["baseline"],
        "EXP-0011a": ["payload"],
        "EXP-0011c-depth-none-leaf-1": ["first-grid"],
        "EXP-0011c-depth-10-leaf-1": ["winner-grid"],
        "EXP-0011c-depth-20-leaf-5": ["last-grid"],
        "EXP-0011d": ["ensemble"],
    }
    reported = experiment.report_threshold_curves(
        curves, "EXP-0011c-depth-10-leaf-1",
    )
    assert reported == {
        "EXP-0009b": ["baseline"],
        "EXP-0011a": ["payload"],
        "EXP-0011c-depth-10-leaf-1": ["winner-grid"],
        "EXP-0011d": ["ensemble"],
    }


def test_equal_weight_ensemble_sweep_pareto_and_incumbent_tie_preference():
    rf = np.array([0.2, 0.8, 0.6])
    xgb = np.array([0.4, 0.4, 1.0])
    assert ((rf + xgb) / 2).tolist() == pytest.approx([0.3, 0.6, 0.8])
    labels = np.array([0, 1, 1])
    curve, point, _ = experiment.selected_point(labels, (rf + xgb) / 2)
    assert len(curve) == 17
    assert point["precision"] >= 0.5
    comparison = experiment.pareto_comparison(
        [
            {"threshold": 0.5, "precision": 0.5, "recall": 0.5},
            {"threshold": 0.6, "precision": 0.8, "recall": 0.4},
        ],
        [{"threshold": 0.5, "precision": 0.6, "recall": 0.5}],
    )
    assert comparison["ensemble_dominates_any_rf_point"]
    points = {
        "EXP-0009b": {"recall": 0.5, "f1": 0.6, "precision": 0.7},
        "EXP-0011d": {"recall": 0.5, "f1": 0.6, "precision": 0.7},
    }
    assert experiment.rank_candidates(points) == "EXP-0009b"


def test_json_normalization_is_strict_for_non_finite_model_defaults():
    assert experiment._json_ready({"missing": float("nan")}) == {"missing": None}


def test_frozen_test_requires_exact_confirmation_before_preparation(monkeypatch):
    called = []
    monkeypatch.setattr(
        experiment, "prepare_pretest_artifacts",
        lambda records=None: called.append("prepared"),
    )
    with pytest.raises(PermissionError, match="exact explicit confirmation"):
        experiment.score_frozen_test_once("wrong")
    assert called == []


def test_fingerprint_mismatch_stops_before_test_materialization(monkeypatch):
    frozen_artifacts = artifacts(monkeypatch)
    data = experiment.prepare_matrices(frozen_artifacts)
    monkeypatch.setattr(
        experiment, "prepare_pretest_artifacts", lambda records=None: frozen_artifacts,
    )
    monkeypatch.setattr(experiment, "prepare_matrices", lambda value: data)
    monkeypatch.setattr(experiment, "fit_final_0011b", lambda value: (
        object(), {
            "sampler": "BorderlineSMOTE",
            "sampler_parameters": {
                "sampling_strategy": "auto", "random_state": 0,
                "k_neighbors": 5, "m_neighbors": 10, "kind": "borderline-1",
            },
            "model": "RandomForestClassifier", "n_estimators": 300,
            "class_weight": None, "random_state": 0, "n_jobs": -1,
            "max_depth": None, "min_samples_leaf": 1,
        }, "wrong-fingerprint",
    ))
    materialized = []
    monkeypatch.setattr(
        experiment, "_test_block", lambda records=None: materialized.append(True),
    )
    with pytest.raises(RuntimeError, match="fingerprint mismatch"):
        experiment.score_frozen_test_once(experiment.FINAL_TEST_CONFIRMATION)
    assert materialized == []


def test_guarded_test_uses_original_features_threshold_and_complete_counts(monkeypatch):
    frozen_artifacts = artifacts(monkeypatch)
    data = experiment.prepare_matrices(frozen_artifacts)
    seen = {}

    class Model:
        def predict_proba(self, matrix):
            seen["feature_count"] = matrix.shape[1]
            probabilities = np.where(np.arange(len(matrix)) % 2, 0.50, 0.49)
            return np.column_stack((1.0 - probabilities, probabilities))

    configuration = {
        "sampler": "BorderlineSMOTE",
        "sampler_parameters": {
            "sampling_strategy": "auto", "random_state": 0,
            "k_neighbors": 5, "m_neighbors": 10, "kind": "borderline-1",
        },
        "resampled_rows": 10, "resampled_normal": 5, "resampled_dos": 5,
        "model": "RandomForestClassifier", "n_estimators": 300,
        "class_weight": None, "random_state": 0, "n_jobs": -1,
        "max_depth": None, "min_samples_leaf": 1,
    }
    monkeypatch.setattr(
        experiment, "prepare_pretest_artifacts", lambda records=None: frozen_artifacts,
    )
    monkeypatch.setattr(experiment, "prepare_matrices", lambda value: data)
    monkeypatch.setattr(experiment, "fit_final_0011b", lambda value: (
        Model(), configuration, experiment.FINAL_FINGERPRINT,
    ))
    test_indices = cadence._contiguous_blocks(30)[2]
    test_buckets = tuple(map(int, test_indices))
    test_rows = tuple(
        item for item in capture()
        if int(item.timestamp // cadence.WINDOW_SECONDS) in test_buckets
    )
    test = cadence.BlockData(
        "test", test_rows, test_buckets,
        {bucket: frozenset(item.categorized_attack for item in test_rows
                           if int(item.timestamp // cadence.WINDOW_SECONDS) == bucket)
         for bucket in test_buckets},
    )
    monkeypatch.setattr(experiment, "_test_block", lambda records=None: test)
    result = experiment.score_frozen_test_once(
        experiment.FINAL_TEST_CONFIRMATION, capture(),
    )
    assert result["status"] == "VALIDATED — ONE FROZEN TEST PASS; NO RERUN"
    assert result["configuration"]["probability_threshold"] == 0.50
    assert result["configuration"]["feature_count"] == len(frozen_artifacts.feature_names)
    assert seen["feature_count"] == len(frozen_artifacts.feature_names) == 33
    assert result["configuration"]["payload_features"] == []
    assert not any(
        "pressure" in name or "available" in name
        for name in result["configuration"]["features"]
    )
    assert result["test_counts"]["normal"] + result["test_counts"]["dos"] == result["test_counts"]["cohort"]
    assert set(result["test_metrics"]) == {
        "precision", "recall", "f1", "fpr", "tn", "fp", "fn", "tp",
    }
    assert result["test_metrics"]["tn"] + result["test_metrics"]["fp"] == result["test_counts"]["normal"]
    assert result["test_metrics"]["fn"] + result["test_metrics"]["tp"] == result["test_counts"]["dos"]


def test_cli_exposes_distinct_guarded_result_path():
    assert experiment.FINAL_TEST_CONFIRMATION != ""
    assert "test" not in experiment.RESULT_PATH.name
    assert experiment.FINAL_RESULT_PATH != experiment.RESULT_PATH


def test_test_only_mutations_do_not_change_pretest_matrices_or_payload(monkeypatch):
    monkeypatch.setattr(cadence, "AUDIT_MIN_FRAMES", 1)
    monkeypatch.setattr(cadence, "AUDIT_MIN_IATS", 1)
    monkeypatch.setattr(cadence, "AUDIT_MIN_WINDOWS", 1)
    rows = capture()
    _, _, test_indices = cadence._contiguous_blocks(30)
    test_buckets = set(int(item) for item in test_indices)
    mutated = tuple(
        replace(item, categorized_attack=42, function_code=99, frame_len_bytes=1)
        if int(item.timestamp // cadence.WINDOW_SECONDS) in test_buckets else item
        for item in rows
    )
    left_artifacts = cadence.prepare_pretest_artifacts(rows, split=synthetic_split())
    right_artifacts = cadence.prepare_pretest_artifacts(mutated, split=synthetic_split())
    left = experiment.prepare_matrices(left_artifacts)
    right = experiment.prepare_matrices(right_artifacts)
    assert left.x_train.tobytes() == right.x_train.tobytes()
    assert left.x_validation.tobytes() == right.x_validation.tobytes()
    assert left.y_train.tobytes() == right.y_train.tobytes()
    assert left.y_validation.tobytes() == right.y_validation.tobytes()


def test_common_selected_point_rule_uses_all_thresholds():
    labels = np.array([0, 0, 1, 1])
    probabilities = np.array([0.1, 0.4, 0.6, 0.9])
    curve, point, rule = experiment.selected_point(labels, probabilities)
    assert [row["threshold"] for row in curve] == list(experiment.THRESHOLDS)
    assert point["recall"] == 1.0
    assert point["precision"] >= 0.5
    assert "maximum recall" in rule
