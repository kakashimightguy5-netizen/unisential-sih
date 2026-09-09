"""Synthetic isolation and selection proofs for EXP-0009 variants."""
from dataclasses import replace

import numpy as np
import pytest

import exp0008_cadence_features as cadence
import exp0009_variants as variants
from exp0009_payload import align_pretest_pressure
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


def synthetic_capture():
    rows = []
    index = 1
    for bucket in range(30):
        category = 6 if bucket % 4 == 3 else 0
        for offset, function in ((0.1, 3), (0.2, 16), (2.1, 3), (2.2, 16)):
            rows.append(record(index, bucket * 5.0 + offset, function=function, category=category))
            index += 1
    return tuple(rows)


def arff(item, pressure):
    return (
        "4", str(item.function_code), str(item.frame_len_bytes),
        *("FORBIDDEN" for _ in range(10)), pressure, "CRC", "0",
        str(item.timestamp), "0", str(item.categorized_attack), "0",
    )


def test_smote_and_rf_configuration_are_frozen_and_validation_is_not_resampled(monkeypatch):
    sampler = variants.make_smote()
    assert sampler.sampling_strategy == "auto"
    assert sampler.k_neighbors == 5
    assert sampler.random_state == 0
    classifier = variants.make_random_forest(class_weight=None)
    assert classifier.n_estimators == 300
    assert classifier.class_weight is None
    assert classifier.random_state == 0 and classifier.n_jobs == -1

    seen = {}

    class SpySMOTE:
        def fit_resample(self, matrix, labels):
            seen["train_rows"] = len(matrix)
            return matrix, labels

    class SpyRF:
        classes_ = np.array([0, 1])

        def fit(self, matrix, labels):
            seen["fit_rows"] = len(matrix)
            return self

        def predict_proba(self, matrix):
            seen["validation_rows"] = len(matrix)
            return np.column_stack((np.ones(len(matrix)), np.zeros(len(matrix))))

    monkeypatch.setattr(variants, "make_smote", lambda: SpySMOTE())
    monkeypatch.setattr(variants, "make_random_forest", lambda **kwargs: SpyRF())
    monkeypatch.setattr(variants, "_semantic_fingerprint", lambda model: "fingerprint")
    artifacts = _synthetic_artifacts(monkeypatch)
    expected_train = len(variants._cohort(artifacts.train_windows))
    expected_validation = len(variants._cohort(artifacts.validation_windows))
    result = variants.run_variant_b(artifacts)
    assert seen == {
        "train_rows": expected_train, "fit_rows": expected_train,
        "validation_rows": expected_validation,
    }
    assert len(result.probabilities) == expected_validation


def _synthetic_artifacts(monkeypatch):
    monkeypatch.setattr(cadence, "AUDIT_MIN_FRAMES", 1)
    monkeypatch.setattr(cadence, "AUDIT_MIN_IATS", 1)
    monkeypatch.setattr(cadence, "AUDIT_MIN_WINDOWS", 1)
    return cadence.prepare_pretest_artifacts(
        synthetic_capture(), split=synthetic_split(),
    )


def test_xgboost_configuration_uses_train_only_class_ratio(monkeypatch):
    artifacts = _synthetic_artifacts(monkeypatch)
    y_train = variants._labels(
        artifacts.train_windows, variants._cohort(artifacts.train_windows),
    )
    ratio = int((y_train == 0).sum()) / int((y_train == 1).sum())
    model = variants.make_xgboost(ratio)
    params = model.get_params()
    assert params["objective"] == "binary:logistic"
    assert params["n_estimators"] == 300
    assert params["random_state"] == 0 and params["n_jobs"] == -1
    assert params["eval_metric"] == "logloss"
    assert params["scale_pos_weight"] == ratio


def test_per_type_schema_active_masks_and_max_or_combiner(monkeypatch):
    artifacts = _synthetic_artifacts(monkeypatch)
    assert len(variants.per_type_feature_names(3)) == 14
    assert all(name.startswith("func_03_") for name in variants.per_type_feature_names(3))
    assert not any("func_10_" in name for name in variants.per_type_feature_names(3))
    left = np.array([0.8, 0.4, 0.9])
    right = np.array([0.7, 0.6, 0.2])
    combined = variants.combine_type_probabilities(
        (left, right), (np.array([True, False, True]), np.array([True, True, False])),
    )
    assert combined.tolist() == [0.8, 0.6, 0.9]
    assert (combined >= 0.5).tolist() == [True, True, True]


def test_variant_ranking_threshold_grid_and_recommendation_tiebreaks():
    metrics = {
        "EXP-0009a": {"f1": 0.6, "recall": 0.7, "precision": 0.5},
        "EXP-0009b": {"f1": 0.6, "recall": 0.7, "precision": 0.5},
        "EXP-0009c": {"f1": 0.5, "recall": 0.9, "precision": 0.4},
    }
    assert variants.select_variant(metrics) == "EXP-0009a"
    assert len(variants.THRESHOLDS) == 17
    assert variants.THRESHOLDS[0] == 0.10 and variants.THRESHOLDS[-1] == 0.90
    labels = np.array([0, 0, 1, 1])
    probabilities = np.array([0.1, 0.6, 0.7, 0.9])
    rows = variants.threshold_sweep(labels, probabilities)
    assert len(rows) == 17
    chosen, rule = variants.recommend_threshold([
        {"threshold": 0.4, "precision": 0.5, "recall": 0.8, "f1": 0.6},
        {"threshold": 0.5, "precision": 0.6, "recall": 0.8, "f1": 0.6},
        {"threshold": 0.6, "precision": 0.6, "recall": 0.8, "f1": 0.6},
    ])
    assert chosen["threshold"] == 0.6
    assert "maximum recall" in rule
    fallback, rule = variants.recommend_threshold([
        {"threshold": 0.4, "precision": 0.4, "recall": 0.8, "f1": 0.6},
        {"threshold": 0.5, "precision": 0.4, "recall": 0.9, "f1": 0.6},
    ])
    assert fallback["threshold"] == 0.5
    assert "fallback" in rule


def test_test_only_txt_and_arff_mutations_cannot_change_pretest_payload():
    rows = synthetic_capture()
    _, _, test_indices = cadence._contiguous_blocks(30)
    test_buckets = set(int(item) for item in test_indices)
    original_arff = tuple(arff(item, str(item.record_index / 100)) for item in rows)
    mutated_rows = tuple(
        replace(item, categorized_attack=42, function_code=99, frame_len_bytes=1)
        if int(item.timestamp // cadence.WINDOW_SECONDS) in test_buckets else item
        for item in rows
    )
    mutated_arff = tuple(
        tuple("TEST-MUTATION" for _ in range(20))
        if int(item.timestamp // cadence.WINDOW_SECONDS) in test_buckets else original_arff[index]
        for index, item in enumerate(rows)
    )
    left = align_pretest_pressure(rows, original_arff, split=synthetic_split())
    right = align_pretest_pressure(
        mutated_rows, mutated_arff, split=synthetic_split(),
    )
    assert dict(left.values) == dict(right.values)


def test_type_aware_payload_stages_receive_injected_canonical_mapper(monkeypatch):
    artifacts = _synthetic_artifacts(monkeypatch)
    rows = synthetic_capture()
    aligned = align_pretest_pressure(
        rows, tuple(arff(item, str(item.record_index / 100)) for item in rows),
        split=synthetic_split(),
    )
    calls = []

    def spy(item, mapping):
        calls.append(item.record_index)
        return cadence.canonical_response_type(item, mapping)

    from exp0009_payload import audit_train_pressure, build_pressure_features, fit_pressure_baselines
    audit_train_pressure(artifacts.inputs.train, aligned, artifacts.type_map, mapper=spy)
    assert calls
    calls.clear()
    baselines = fit_pressure_baselines(
        artifacts.inputs.train, aligned, artifacts.type_map, mapper=spy,
    )
    assert calls
    calls.clear()
    build_pressure_features(
        artifacts.inputs.validation, aligned, artifacts.type_map, baselines, mapper=spy,
    )
    assert calls


def test_frozen_test_confirmation_guard_and_no_implementation_before_signoff():
    with pytest.raises(PermissionError):
        variants.score_frozen_test_once("", {})
    assert variants.FINAL_TEST_CONFIRMATION == "SCORE-EXP-0009-FROZEN-TEST-ONCE"
    with pytest.raises(RuntimeError, match="not implemented before sign-off"):
        variants.score_frozen_test_once(variants.FINAL_TEST_CONFIRMATION, {})
