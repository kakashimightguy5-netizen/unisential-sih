"""Synthetic construction and TEST-blindness proofs for EXP-0013.

EXP-0013 is the first genuinely TEST-blind frozen Type 1 DoS evaluation, built on
the corrected ``verified-egress-5s-exp0008-pretest-v1`` manifest. These tests do
not touch the real dataset or the real frozen TEST tail.
"""
import math
from dataclasses import replace

import numpy as np
import pytest

import exp0008_cadence as cadence_runner
import exp0008_cadence_features as cadence
import exp0013_frozen_test as experiment
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
        experiment.EXPECTED_SPLIT_ID, experiment.EXPECTED_MEMBERSHIP_SHA256,
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


def artifacts(monkeypatch):
    monkeypatch.setattr(cadence, "AUDIT_MIN_FRAMES", 1)
    monkeypatch.setattr(cadence, "AUDIT_MIN_IATS", 1)
    monkeypatch.setattr(cadence, "AUDIT_MIN_WINDOWS", 1)
    return cadence.prepare_pretest_artifacts(capture(), split=synthetic_split())


# ------------------------------------------------------------------ frozen recipe

def test_frozen_configuration_constants_match_exp0011b_recipe():
    assert experiment.PROBABILITY_THRESHOLD == 0.50
    assert experiment.FROZEN_TEST_CONFIRMATION == "SCORE-EXP-0013-FROZEN-TEST-ONCE"
    assert experiment.EXPECTED_SPLIT_ID == "verified-egress-5s-exp0008-pretest-v1"
    assert experiment.EXPECTED_MEMBERSHIP_SHA256 == (
        "0e912e147d088aaed05e95bda04c6a46c72ed4dd16aafb6966c9e2aab26859e6"
    )
    # The fit path is imported directly from EXP-0011b so the model recipe and its
    # semantic fingerprint gate cannot drift.
    from exp0011_validation import FINAL_FINGERPRINT, fit_final_0011b
    assert experiment.fit_final_0011b is fit_final_0011b
    assert experiment.FINAL_FINGERPRINT == FINAL_FINGERPRINT


def test_comparison_context_marks_invalidated_and_out_of_scope_rows():
    rows = experiment.COMPARISON_CONTEXT
    for name in ("EXP-0008-detector-a", "EXP-0008-detector-b", "EXP-0009b", "EXP-0011b"):
        assert "INVALIDATED" in rows[name]["status"]
    assert "OUT OF SCOPE" in rows["EXP-0005b"]["status"]
    assert "CONTEXT" in rows["EXP-0004"]["status"]
    assert "must NOT be cited" in rows["EXP-0011b"]["status"]
    # The retracted EXP-0011b frozen numbers are retained verbatim for audit only.
    assert rows["EXP-0011b"]["recall"] == pytest.approx(0.2694300518134715)


# ------------------------------------------------------------------ guard: token

def test_frozen_test_requires_exact_confirmation_before_any_work(monkeypatch):
    called = []
    monkeypatch.setattr(
        experiment, "_assert_corrected_manifest", lambda: called.append("manifest"),
    )
    monkeypatch.setattr(
        experiment, "prepare_pretest_artifacts",
        lambda records=None: called.append("prepared"),
    )
    with pytest.raises(PermissionError, match="exact explicit confirmation"):
        experiment.score_frozen_test_once("wrong")
    assert called == []


# ------------------------------------------------------------------ guard: manifest

def test_manifest_guard_rejects_wrong_split_id(monkeypatch):
    wrong = cadence.PreTestSplit(
        "some-other-split", experiment.EXPECTED_MEMBERSHIP_SHA256,
        (0, 1, 2), (4, 5), (3,),
    )
    monkeypatch.setattr(experiment, "load_pretest_split", lambda: wrong)
    with pytest.raises(RuntimeError, match="corrected verified-egress"):
        experiment._assert_corrected_manifest()


def test_manifest_guard_rejects_wrong_checksum(monkeypatch):
    wrong = cadence.PreTestSplit(
        experiment.EXPECTED_SPLIT_ID, "0" * 64, (0, 1, 2), (4, 5), (3,),
    )
    monkeypatch.setattr(experiment, "load_pretest_split", lambda: wrong)
    with pytest.raises(RuntimeError, match="membership checksum"):
        experiment._assert_corrected_manifest()


def test_manifest_guard_passes_on_corrected_manifest(monkeypatch):
    ok = cadence.PreTestSplit(
        experiment.EXPECTED_SPLIT_ID, experiment.EXPECTED_MEMBERSHIP_SHA256,
        (0, 1, 2), (4, 5), (3,),
    )
    monkeypatch.setattr(experiment, "load_pretest_split", lambda: ok)
    experiment._assert_corrected_manifest()


# ------------------------------------------------------------------ TEST construction

def test_test_block_starts_after_validation_end_and_drops_two_guard_windows(monkeypatch):
    monkeypatch.setattr(cadence_runner, "load_pretest_split", synthetic_split)
    block = cadence_runner._test_block(capture())
    # final VALIDATION bucket is 22; every emitted egress window after it is 23..29,
    # and the first two (23, 24) are discarded as guards.
    assert block.emitted_buckets == (25, 26, 27, 28, 29)
    assert min(math.floor(r.timestamp / cadence.WINDOW_SECONDS) for r in block.records) == 25


# ------------------------------------------------------------------ guarded score

def test_guarded_score_uses_33_features_threshold_050_and_complete_counts(monkeypatch):
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
    monkeypatch.setattr(experiment, "_assert_corrected_manifest", lambda: None)
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
        experiment.FROZEN_TEST_CONFIRMATION, capture(),
    )
    assert result["status"] == "VALIDATED — ONE TEST-BLIND FROZEN PASS; NO RERUN"
    assert result["experiment"] == "EXP-0013"
    cfg = result["frozen_configuration"]
    assert cfg["probability_threshold"] == 0.50
    assert cfg["feature_count"] == len(frozen_artifacts.feature_names) == 33
    assert seen["feature_count"] == 33
    assert cfg["payload_features"] == [] and cfg["lag_or_trend_features"] == []
    assert cfg["semantic_fingerprint_sha256"] == experiment.FINAL_FINGERPRINT
    assert "differs from EXP-0011b" in cfg["fingerprint_note"]
    assert not any(
        "pressure" in name or "available" in name or "lag" in name
        for name in cfg["features"]
    )
    counts = result["test_counts"]
    assert counts["normal"] + counts["dos"] == counts["cohort"]
    metrics = result["test_metrics"]
    assert set(metrics) == {"precision", "recall", "f1", "fpr", "tn", "fp", "fn", "tp"}
    assert metrics["tn"] + metrics["fp"] == counts["normal"]
    assert metrics["fn"] + metrics["tp"] == counts["dos"]
    assert result["manifest"]["split_id"] == experiment.EXPECTED_SPLIT_ID


def test_wrong_model_knobs_stop_before_test_materialization(monkeypatch):
    frozen_artifacts = artifacts(monkeypatch)
    data = experiment.prepare_matrices(frozen_artifacts)
    monkeypatch.setattr(experiment, "_assert_corrected_manifest", lambda: None)
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
            "max_depth": 10, "min_samples_leaf": 1,
        }, "irrelevant",
    ))
    materialized = []
    monkeypatch.setattr(
        experiment, "_test_block", lambda records=None: materialized.append(True),
    )
    with pytest.raises(RuntimeError, match="Random Forest configuration mismatch"):
        experiment.score_frozen_test_once(experiment.FROZEN_TEST_CONFIRMATION)
    assert materialized == []


def test_frozen_configuration_assertion_ignores_fingerprint_value():
    # EXP-0013 legitimately produces a fresh fingerprint; only the knobs are gated.
    experiment._assert_frozen_configuration({
        "sampler": "BorderlineSMOTE",
        "sampler_parameters": {
            "sampling_strategy": "auto", "random_state": 0,
            "k_neighbors": 5, "m_neighbors": 10, "kind": "borderline-1",
        },
        "model": "RandomForestClassifier", "n_estimators": 300,
        "class_weight": None, "random_state": 0, "n_jobs": -1,
        "max_depth": None, "min_samples_leaf": 1,
    })


# ------------------------------------------------------------------ TEST-blindness

def test_test_only_mutations_do_not_change_pretest_matrices(monkeypatch):
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
    left = experiment.prepare_matrices(
        cadence.prepare_pretest_artifacts(rows, split=synthetic_split()),
    )
    right = experiment.prepare_matrices(
        cadence.prepare_pretest_artifacts(mutated, split=synthetic_split()),
    )
    assert left.x_train.tobytes() == right.x_train.tobytes()
    assert left.x_validation.tobytes() == right.x_validation.tobytes()
    assert left.y_train.tobytes() == right.y_train.tobytes()
    assert left.y_validation.tobytes() == right.y_validation.tobytes()


def test_pretest_construction_never_enumerates_test_windows(monkeypatch):
    frozen_artifacts = artifacts(monkeypatch)
    assert frozen_artifacts.inputs.test_window_count is None
    assert frozen_artifacts.inputs.split_id == experiment.EXPECTED_SPLIT_ID


# ------------------------------------------------------------------ CLI surface

def test_cli_requires_the_score_flag_and_the_confirm_token(monkeypatch, capsys):
    assert experiment.RESULT_PATH.name == "exp0013_frozen_test.json"
    monkeypatch.setattr("sys.argv", ["exp0013_frozen_test.py"])
    with pytest.raises(SystemExit):
        experiment.main()
    monkeypatch.setattr("sys.argv", ["exp0013_frozen_test.py", "--confirm", "x"])
    with pytest.raises(SystemExit):
        experiment.main()
